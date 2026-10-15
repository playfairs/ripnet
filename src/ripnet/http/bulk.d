module ripnet.http.bulk;

import core.thread : Thread;
import core.time : Duration, MonoTime, dur;
import ripnet.http.client : HttpRequest, HttpResponse, hostnameFromUrl, perform, validateRequest;
import std.string : indexOf, toLower;
import std.file : getSize, read;
import std.datetime.stopwatch : StopWatch, AutoStart;

private enum size_t maxRequests = 1000;
private enum size_t maxConcurrency = 8;
private enum uint maxRequestsPerSecond = 10;
private enum uint maxBatchDurationSeconds = 120;
private enum size_t maxBatchResponseBytes = 16777216;

public struct BulkOptions
{
    HttpRequest request;
    string authorizedHost;
    uint requestCount = 1;
    uint concurrency = 1;
    uint maxRequestsPerSecond = 1;
    bool dryRun;
}

public struct BulkResult
{
    HttpResponse[] responses;
    size_t plannedRequests;
    size_t succeeded;
    size_t failed;
    size_t responseBytes;
    double elapsedMs;
    bool dryRun;
    string error;
}

private class Scheduler
{
    size_t nextIndex;
    size_t requestCount;
    Duration interval;
    MonoTime nextStart;

    this(size_t requestCount, uint requestsPerSecond)
    {
        this.requestCount = requestCount;
        interval = dur!"msecs"(1000 / requestsPerSecond);
        nextStart = MonoTime.currTime;
    }

    bool reserve(out size_t index, out Duration delay)
    {
        synchronized (this)
        {
            if (nextIndex >= requestCount)
                return false;
            index = nextIndex++;
            auto now = MonoTime.currTime;
            if (now < nextStart)
                delay = nextStart - now;
            else
                delay = dur!"msecs"(0);
            nextStart = (now + delay) + interval;
            return true;
        }
    }
}

public BulkResult execute(BulkOptions options)
{
    BulkResult result;
    result.dryRun = options.dryRun;
    result.elapsedMs = 0;
    if (options.requestCount == 0 || options.requestCount > maxRequests)
    {
        result.error = "request count must be between 1 and 1000";
        return result;
    }
    if (options.concurrency == 0 || options.concurrency > maxConcurrency)
    {
        result.error = "concurrency must be between 1 and 8";
        return result;
    }
    if (options.maxRequestsPerSecond == 0 || options.maxRequestsPerSecond > maxRequestsPerSecond)
    {
        result.error = "maximum request rate must be between 1 and 10 requests per second";
        return result;
    }
    if (options.requestCount > options.maxRequestsPerSecond * maxBatchDurationSeconds)
    {
        result.error = "batch schedule would exceed the 120-second duration ceiling";
        return result;
    }
    result.plannedRequests = options.requestCount;

    string urlError;
    auto targetHost = hostnameFromUrl(options.request.url, urlError);
    if (urlError.length)
    {
        result.error = urlError;
        return result;
    }
    if (!options.authorizedHost.length || toLower(options.authorizedHost) != toLower(targetHost))
    {
        result.error = "--allow-host must exactly match the request URL host";
        return result;
    }
    auto validationError = validateRequest(options.request);
    if (validationError.length)
    {
        result.error = validationError;
        return result;
    }

    size_t bodyLength = options.request.body.length;
    foreach (index, field; options.request.formFields)
    {
        if (field.indexOf('=') <= 0 || field.length > maxBatchResponseBytes / 3)
        {
            result.error = "form fields must use KEY=VALUE and fit the batch transfer limit";
            return result;
        }
        auto encodedUpperBound = field.length * 3 + 1 + (index ? 1 : 0);
        if (encodedUpperBound > maxBatchResponseBytes - bodyLength)
        {
            result.error = "repeated form bodies would exceed the 16 MiB batch transfer limit";
            return result;
        }
        bodyLength += encodedUpperBound;
    }
    if (options.request.bodyFile.length)
    {
        ulong bodyFileSize;
        try
            bodyFileSize = getSize(options.request.bodyFile);
        catch (Exception exception)
        {
            result.error = "could not inspect request body file: " ~ exception.msg;
            return result;
        }
        if (bodyFileSize > maxBatchResponseBytes / options.requestCount)
        {
            result.error = "repeated request bodies would exceed the 16 MiB batch transfer limit";
            return result;
        }
        bodyLength = cast(size_t) bodyFileSize;
        if (!options.dryRun || options.request.jsonBody)
        {
            try
            {
                auto fileBody = cast(ubyte[]) read(options.request.bodyFile);
                bodyLength = fileBody.length;
                options.request.body = cast(string) fileBody;
                options.request.bodyFile = "";
            }
            catch (Exception exception)
            {
                result.error = "could not read request body file: " ~ exception.msg;
                return result;
            }
        }
    }
    if (bodyLength > maxBatchResponseBytes / options.requestCount)
    {
        result.error = "repeated request bodies would exceed the 16 MiB batch transfer limit";
        return result;
    }

    auto requestBytes = bodyLength * options.requestCount;
    auto responseBudget = maxBatchResponseBytes - requestBytes;
    if (responseBudget < options.requestCount)
    {
        result.error
            = "request bodies leave insufficient response budget under the 16 MiB batch limit";
        return result;
    }
    validationError = validateRequest(options.request);
    if (validationError.length)
    {
        result.error = validationError;
        return result;
    }
    if (options.dryRun)
        return result;

    auto perResponseLimit = responseBudget / options.requestCount;
    options.request.maxResponseBytes = options.request.maxResponseBytes < perResponseLimit
        ? options.request.maxResponseBytes : perResponseLimit;
    options.request.followRedirects = false;

    result.responses.length = options.requestCount;
    auto scheduler = new Scheduler(options.requestCount, options.maxRequestsPerSecond);
    auto workerCount = options.concurrency < options.requestCount
        ? options.concurrency : options.requestCount;
    auto watch = StopWatch(AutoStart.yes);
    Thread[] workers;
    foreach (_; 0 .. workerCount)
    {
        auto worker = new Thread({
            size_t index;
            Duration delay;
            while (scheduler.reserve(index, delay))
            {
                if (delay > dur!"msecs"(0))
                    Thread.sleep(delay);
                result.responses[index] = perform(options.request);
            }
        });
        worker.start();
        workers ~= worker;
    }
    foreach (worker; workers)
        worker.join();

    result.elapsedMs = watch.peek.total!"msecs";
    foreach (response; result.responses)
    {
        if (response.transportSuccess)
            ++result.succeeded;
        else
            ++result.failed;
        result.responseBytes += response.body.length;
    }
    return result;
}
