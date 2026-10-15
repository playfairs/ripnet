module ripnet.http.client;

import std.array : Appender, appender;
import std.file : getSize, read;
import std.string : fromStringz, indexOf, startsWith, strip, toLower, toStringz;

private struct CURL;
private struct CURLU;
private struct curl_slist;

extern (C)
{
    int curl_global_init(ulong flags);
    CURLU* curl_url();
    void curl_url_cleanup(CURLU* handle);
    int curl_url_get(const CURLU* handle, int part, char** value, uint flags);
    int curl_url_set(CURLU* handle, int part, const(char)* value, uint flags);
    const(char)* curl_url_strerror(int code);
    CURL* curl_easy_init();
    void curl_easy_cleanup(CURL* handle);
    int curl_easy_setopt(CURL* handle, int option, ...);
    int curl_easy_getinfo(CURL* handle, int info, ...);
    int curl_easy_perform(CURL* handle);
    const(char)* curl_easy_strerror(int code);
    char* curl_easy_escape(CURL* handle, const(char)* value, int length);
    void curl_free(void* pointer);
    curl_slist* curl_slist_append(curl_slist* list, const(char)* value);
    void curl_slist_free_all(curl_slist* list);
}

private enum int curlOk = 0;
private enum int curlUrl = 10002;
private enum int curlProxy = 10004;
private enum int curlUserPassword = 10005;
private enum int curlErrorBuffer = 10010;
private enum int curlWriteData = 10001;
private enum int curlWriteFunction = 20011;
private enum int curlHeaderData = 10029;
private enum int curlHeaderFunction = 20079;
private enum int curlPostFields = 10015;
private enum int curlPostFieldsSize = 30120;
private enum int curlCookie = 10022;
private enum int curlHttpHeader = 10023;
private enum int curlCustomRequest = 10036;
private enum int curlNoBody = 44;
private enum int curlFollowLocation = 52;
private enum int curlSslVerifyPeer = 64;
private enum int curlMaxRedirects = 68;
private enum int curlHttpGet = 80;
private enum int curlSslVerifyHost = 81;
private enum int curlHttpVersion = 84;
private enum int curlAcceptEncoding = 10102;
private enum int curlHttpAuth = 107;
private enum int curlTimeoutMs = 155;
private enum int curlConnectTimeoutMs = 156;
private enum int curlProtocols = 181;
private enum int curlRedirectProtocols = 182;
private enum int curlUrlPart = 0;
private enum int curlUrlPartScheme = 1;
private enum int curlUrlPartHost = 5;
private enum uint curlUrlDisallowUser = 1 << 5;
private enum int curlInfoResponseCode = 0x200002;
private enum int curlInfoTotalTime = 0x300003;
private enum int curlInfoConnectTime = 0x300005;
private enum int curlInfoStartTransferTime = 0x300011;

private __gshared int globalInitStatus = -1;

shared static this()
{
    globalInitStatus = curl_global_init(3);
}

public struct HttpRequest
{
    string url;
    string method = "GET";
    string[] headers;
    string[] query;
    string body;
    string bodyFile;
    string contentType;
    string[] formFields;
    string bearerToken;
    string basicAuth;
    string cookie;
    string proxy;
    uint timeoutMs = 10000;
    uint maxRedirects = 5;
    size_t maxResponseBytes = 1048576;
    bool followRedirects = true;
    bool allowTrace;
    bool jsonBody;
    bool insecureTls;
}

public struct HttpResponse
{
    long statusCode;
    string[] headers;
    ubyte[] body;
    double totalMs;
    double connectMs;
    double firstByteMs;
    string error;
    bool transportSuccess;
}

private struct TransferContext
{
    Appender!(ubyte[])
    body;
    string[] headers;
    size_t maxResponseBytes;
    bool tooLarge;
}

private extern (C) size_t writeBody(const(ubyte)* data, size_t size, size_t count, void* userData)
{
    auto context = cast(TransferContext*) userData;
    if (size && count > size_t.max / size)
    {
        context.tooLarge = true;
        return 0;
    }
    auto bytes = size * count;
    if (bytes > context.maxResponseBytes - context.body.data.length)
    {
        context.tooLarge = true;
        return 0;
    }
    context.body.put(data[0 .. bytes]);
    return bytes;
}

private extern (C) size_t writeHeader(const(char)* data, size_t size, size_t count, void* userData)
{
    if (size && count > size_t.max / size)
        return 0;
    auto bytes = size * count;
    auto context = cast(TransferContext*) userData;
    auto line = data[0 .. bytes].idup;
    if (line.startsWith("HTTP/"))
        context.headers = [];
    else if (line.strip.length)
        context.headers ~= line.strip.idup;
    return bytes;
}

private bool validMethod(string method)
{
    if (!method.length)
        return false;
    foreach (character; method)
    {
        auto alphanumeric = (character >= 'a' && character <= 'z')
            || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9');
        auto punctuation = "!#$%&'*+-.^_`|~".indexOf(character) >= 0;
        if (!alphanumeric && !punctuation)
            return false;
    }
    return true;
}

private bool safeHeader(string header)
{
    auto separator = header.indexOf(':');
    if (separator <= 0)
        return false;
    foreach (character; header)
        if (character == '\r' || character == '\n' || character == '\0')
            return false;
    foreach (character; header[0 .. separator])
    {
        auto alphanumeric = (character >= 'a' && character <= 'z')
            || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9');
        auto punctuation = "!#$%&'*+-.^_`|~".indexOf(character) >= 0;
        if (!alphanumeric && !punctuation)
            return false;
    }
    return true;
}

private string queryUrl(CURL* handle, string url, string[] parameters, out string error)
{
    auto fragment = url.indexOf('#');
    auto suffix = fragment < 0 ? "" : url[fragment .. $];
    auto result = fragment < 0 ? url : url[0 .. fragment];
    foreach (parameter; parameters)
    {
        auto separator = parameter.indexOf('=');
        if (separator <= 0)
        {
            error = "query parameters must use KEY=VALUE";
            return "";
        }
        auto key = escapeQueryPart(handle, parameter[0 .. separator]);
        auto value = escapeQueryPart(handle, parameter[separator + 1 .. $]);
        if (key is null || value is null)
        {
            error = "could not encode query parameter";
            return "";
        }
        if (result.indexOf('?') < 0)
            result ~= '?';
        else if (result.length && result[$ - 1] != '?' && result[$ - 1] != '&')
            result ~= '&';
        result ~= key ~ "=" ~ value;
    }
    return result ~ suffix;
}

private string escapeQueryPart(CURL* handle, string value)
{
    auto escaped = curl_easy_escape(handle, value.toStringz, cast(int) value.length);
    if (escaped is null)
        return null;
    scope (exit)
        curl_free(escaped);
    return fromStringz(escaped).idup;
}

private string encodeForm(CURL* handle, string[] fields, out string error)
{
    string result;
    foreach (field; fields)
    {
        auto separator = field.indexOf('=');
        if (separator <= 0)
        {
            error = "form fields must use KEY=VALUE";
            return "";
        }
        auto key = escapeQueryPart(handle, field[0 .. separator]);
        auto value = escapeQueryPart(handle, field[separator + 1 .. $]);
        if (key is null || value is null)
        {
            error = "could not encode form field";
            return "";
        }
        if (result.length)
            result ~= '&';
        result ~= key ~ "=" ~ value;
    }
    return result;
}

public string validateRequest(HttpRequest request)
{
    if (!request.url.length)
        return "missing URL";
    if (!request.timeoutMs)
        return "timeout must be greater than zero";
    if (request.timeoutMs > 300000)
        return "timeout cannot exceed 300000 milliseconds";
    if (request.maxResponseBytes == 0 || request.maxResponseBytes > 16777216)
        return "maximum response size must be between 1 byte and 16 MiB";
    if (request.maxRedirects > 10)
        return "redirect limit must be between 0 and 10";
    if (!validMethod(request.method))
        return "invalid HTTP method token";
    if (toLower(request.method) == "trace" && !request.allowTrace)
        return "TRACE requires explicit --allow-trace opt-in";
    if (request.basicAuth.length)
    {
        auto separator = request.basicAuth.indexOf(':');
        if (separator <= 0)
            return "basic authentication must use USER:PASSWORD";
        if (request.bearerToken.length)
            return "basic and bearer authentication cannot be combined";
        foreach (character; request.basicAuth)
            if (character == '\r' || character == '\n' || character == '\0')
                return "basic authentication contains a control character";
    }
    if (request.body.length && request.bodyFile.length)
        return "--body and --body-file cannot be combined";
    if (request.formFields.length && (request.body.length || request.bodyFile.length))
        return "--form cannot be combined with --body or --body-file";
    if (request.formFields.length && request.jsonBody)
        return "--form cannot be combined with --json-body";
    if ((request.body.length || request.bodyFile.length
            || request.formFields.length) && (toLower(request.method) == "get"
            || toLower(request.method) == "head"))
        return "GET and HEAD requests cannot include a body";
    if (request.formFields.length)
    {
        auto method = toLower(request.method);
        if (method != "post" && method != "put" && method != "patch")
            return "--form requires POST, PUT, or PATCH";
    }
    if (request.jsonBody && request.contentType.length
            && !toLower(request.contentType).startsWith("application/json"))
        return "--json-body conflicts with the supplied content type";
    if (request.contentType.length && !safeHeader("Content-Type: " ~ request.contentType))
        return "invalid Content-Type value";
    foreach (header; request.headers)
    {
        if (!safeHeader(header))
            return "invalid request header; expected a valid NAME: VALUE without control characters";
        auto separator = header.indexOf(':');
        auto name = toLower(header[0 .. separator].strip);
        if (request.contentType.length && name == "content-type")
            return "--content-type/--json-body cannot be combined with a Content-Type header";
        if (request.bearerToken.length && name == "authorization")
            return "--bearer cannot be combined with an Authorization header";
        if (request.basicAuth.length && name == "authorization")
            return "--basic-auth cannot be combined with an Authorization header";
    }
    if (request.jsonBody && request.body.length)
    {
        import std.json : parseJSON;

        try
            parseJSON(request.body);
        catch (Exception exception)
            return "invalid JSON request body: " ~ exception.msg;
    }
    auto urlError = validateUrl(request.url);
    if (urlError.length)
        return urlError;
    return "";
}

private string parseUrlParts(string url, out string scheme, out string host)
{
    auto parsed = curl_url();
    if (parsed is null)
        return "could not allocate a URL parser";
    scope (exit)
        curl_url_cleanup(parsed);

    auto parseCode = curl_url_set(parsed, curlUrlPart, url.toStringz, curlUrlDisallowUser);
    if (parseCode != 0)
        return "invalid URL: " ~ fromStringz(curl_url_strerror(parseCode)).idup;

    char* schemePart;
    auto schemeCode = curl_url_get(parsed, curlUrlPartScheme, &schemePart, 0);
    if (schemeCode != 0)
        return "URL must be an absolute http:// or https:// URL";
    scope (exit)
        curl_free(schemePart);

    char* hostPart;
    auto hostCode = curl_url_get(parsed, curlUrlPartHost, &hostPart, 0);
    if (hostCode != 0)
        return "URL must include a host";
    scope (exit)
        curl_free(hostPart);

    scheme = fromStringz(schemePart).idup;
    host = fromStringz(hostPart).idup;
    return "";
}

public string hostnameFromUrl(string url, out string error)
{
    string scheme;
    string host;
    error = parseUrlParts(url, scheme, host);
    return error.length ? "" : host;
}

private string validateUrl(string url)
{
    string scheme;
    string host;
    auto error = parseUrlParts(url, scheme, host);
    if (error.length)
        return error;

    auto normalizedScheme = toLower(scheme);
    if (normalizedScheme != "http" && normalizedScheme != "https")
        return "URL scheme must be http or https";
    if (!host.length)
        return "URL must include a host";
    return "";
}

private int setLong(CURL* handle, int option, long value)
{
    return curl_easy_setopt(handle, option, value);
}

private int setString(CURL* handle, int option, string value)
{
    return curl_easy_setopt(handle, option, value.toStringz);
}

public HttpResponse perform(HttpRequest request)
{
    import std.stdio : stderr, writeln;

    HttpResponse response;
    response.totalMs = 0;
    response.connectMs = 0;
    response.firstByteMs = 0;
    auto validationError = validateRequest(request);
    if (validationError.length)
    {
        response.error = validationError;
        return response;
    }
    if (globalInitStatus != curlOk)
    {
        response.error = "libcurl initialization failed";
        return response;
    }

    auto easy = curl_easy_init();
    if (easy is null)
    {
        response.error = "could not allocate an HTTP client handle";
        return response;
    }
    scope (exit)
        curl_easy_cleanup(easy);

    auto url = queryUrl(easy, request.url, request.query, response.error);
    if (response.error.length)
        return response;

    ubyte[] body;
    if (request.bodyFile.length)
    {
        ulong fileSize;
        try
            fileSize = getSize(request.bodyFile);
        catch (Exception exception)
        {
            response.error = "could not inspect request body file: " ~ exception.msg;
            return response;
        }
        if (fileSize > 16777216)
        {
            response.error = "request body exceeds 16 MiB";
            return response;
        }
        try
            body = cast(ubyte[]) read(request.bodyFile);
        catch (Exception exception)
        {
            response.error = "could not read request body file: " ~ exception.msg;
            return response;
        }
        if (body.length > 16777216)
        {
            response.error = "request body exceeds 16 MiB";
            return response;
        }
    }
    else
        body = cast(ubyte[]) request.body.dup;
    if (request.formFields.length)
    {
        auto formBody = encodeForm(easy, request.formFields, response.error);
        if (response.error.length)
            return response;
        body = cast(ubyte[]) formBody.dup;
        request.contentType = "application/x-www-form-urlencoded";
    }
    if (request.jsonBody)
    {
        import std.json : parseJSON;

        try
            parseJSON(cast(string)
                    body);
        catch (Exception exception)
        {
            response.error = "invalid JSON request body: " ~ exception.msg;
            return response;
        }
        request.contentType = "application/json";
    }
    if (body.length > 16777216)
    {
        response.error = "request body exceeds 16 MiB";
        return response;
    }
    import std.stdio : stderr, writeln;

    curl_slist* requestHeaders;
    scope (exit)
    {
        if (requestHeaders !is null)
            curl_slist_free_all(requestHeaders);
    }

    foreach (header; request.headers)
    {
        requestHeaders = curl_slist_append(requestHeaders, header.toStringz);
        if (requestHeaders is null)
        {
            response.error = "could not allocate request headers";
            return response;
        }
    }
    if (request.contentType.length)
    {
        foreach (header; request.headers)
            if (toLower(header[0 .. header.indexOf(':')].strip) == "content-type")
            {
                response.error
                    = "--content-type/--json-body cannot be combined with a Content-Type header";
                return response;
            }
        requestHeaders = curl_slist_append(requestHeaders,
                ("Content-Type: " ~ request.contentType).toStringz);
        if (requestHeaders is null)
        {
            response.error = "could not allocate Content-Type header";
            return response;
        }
    }
    if (request.bearerToken.length)
    {
        foreach (header; request.headers)
            if (toLower(header[0 .. header.indexOf(':')].strip) == "authorization")
            {
                response.error = "--bearer cannot be combined with an Authorization header";
                return response;
            }
        foreach (character; request.bearerToken)
            if (character == '\r' || character == '\n' || character == '\0')
            {
                response.error = "bearer token contains a control character";
                return response;
            }
        requestHeaders = curl_slist_append(requestHeaders,
                ("Authorization: Bearer " ~ request.bearerToken).toStringz);
        if (requestHeaders is null)
        {
            response.error = "could not allocate bearer authorization header";
            return response;
        }
    }

    TransferContext context;
    context.body = appender!(ubyte[])();
    context.maxResponseBytes = request.maxResponseBytes;
    char[256] errorBuffer = 0;

    auto optionError = "";
    if (setString(easy, curlUrl, url) != curlOk)
        optionError = "could not set request URL";
    else if (setString(easy, curlCustomRequest, request.method) != curlOk)
        optionError = "could not set request method";
    else if (setLong(easy, curlTimeoutMs, request.timeoutMs) != curlOk
            || setLong(easy, curlConnectTimeoutMs, request.timeoutMs) != curlOk)
        optionError = "could not set request timeout";
    else if (setLong(easy, curlFollowLocation, request.followRedirects
            ? 1 : 0) != curlOk || setLong(easy, curlMaxRedirects, request.maxRedirects) != curlOk)
        optionError = "could not set redirect policy";
    else if (setLong(easy, curlSslVerifyPeer, request.insecureTls ? 0 : 1) != curlOk
            || setLong(easy, curlSslVerifyHost, request.insecureTls ? 0 : 2) != curlOk)
        optionError = "could not set TLS verification policy";
    else if (setLong(easy, curlProtocols, 3) != curlOk || setLong(easy,
            curlRedirectProtocols, 3) != curlOk)
        optionError = "could not restrict request protocols to HTTP and HTTPS";
    else if (setLong(easy, curlHttpVersion, 4) != curlOk)
        optionError = "could not enable HTTP/2 TLS negotiation";
    else if (setString(easy, curlAcceptEncoding, "") != curlOk)
        optionError = "could not enable supported response compression";
    else if (setString(easy, curlErrorBuffer, cast(string) errorBuffer[]) != curlOk)
        optionError = "could not configure the transport error buffer";
    else if (curl_easy_setopt(easy, curlWriteFunction, &writeBody) != curlOk
            || curl_easy_setopt(easy, curlWriteData, cast(void*)&context) != curlOk
            || curl_easy_setopt(easy, curlHeaderFunction,
                &writeHeader) != curlOk || curl_easy_setopt(easy,
                curlHeaderData, cast(void*)&context) != curlOk)
        optionError = "could not configure response callbacks";
    else if (requestHeaders !is null && curl_easy_setopt(easy, curlHttpHeader,
            requestHeaders) != curlOk)
        optionError = "could not configure request headers";

    auto method = toLower(request.method);
    if (!optionError.length && method == "head" && setLong(easy, curlNoBody, 1) != curlOk)
        optionError = "could not configure HEAD request";
    if (!optionError.length && (method == "post" || method == "put"
            || method == "patch" || body.length))
    {
        auto bodyPointer = body.length ? cast(void*)
        body.ptr : null;
        if (curl_easy_setopt(easy, curlPostFields, bodyPointer) != curlOk
                || curl_easy_setopt(easy, curlPostFieldsSize, cast(long)
                    body.length) != curlOk)
            optionError = "could not configure request body";
    }
    if (!optionError.length && method == "get" && setLong(easy, curlHttpGet, 1) != curlOk)
        optionError = "could not configure GET request";
    if (!optionError.length && request.basicAuth.length)
    {
        if (setString(easy, curlUserPassword, request.basicAuth) != curlOk
                || setLong(easy, curlHttpAuth, 1) != curlOk)
            optionError = "could not configure basic authentication";
    }
    if (!optionError.length && request.cookie.length && setString(easy,
            curlCookie, request.cookie) != curlOk)
        optionError = "could not configure request cookies";
    if (!optionError.length && request.proxy.length && setString(easy,
            curlProxy, request.proxy) != curlOk)
        optionError = "could not configure proxy";
    if (optionError.length)
    {
        response.error = optionError;
        return response;
    }

    if (request.insecureTls)
        stderr.writeln("warning: TLS certificate verification is disabled");

    auto code = curl_easy_perform(easy);
    if (context.tooLarge)
    {
        response.error = "response exceeded configured size limit";
        return response;
    }
    if (code != curlOk)
    {
        auto detail = errorBuffer[0] ? fromStringz(errorBuffer.ptr).idup
            : fromStringz(curl_easy_strerror(code)).idup;
        response.error = detail;
        return response;
    }

    response.transportSuccess = true;
    response.headers = context.headers;
    response.body = context.body.data;
    curl_easy_getinfo(easy, curlInfoResponseCode, &response.statusCode);
    double seconds;
    if (curl_easy_getinfo(easy, curlInfoTotalTime, &seconds) == curlOk)
        response.totalMs = seconds * 1000;
    if (curl_easy_getinfo(easy, curlInfoConnectTime, &seconds) == curlOk)
        response.connectMs = seconds * 1000;
    if (curl_easy_getinfo(easy, curlInfoStartTransferTime, &seconds) == curlOk)
        response.firstByteMs = seconds * 1000;
    return response;
}
