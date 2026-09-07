module buildinfo;

enum versionString = trimVersion(import("VERSION"));

string trimVersion(string value) {
	while (value.length > 0 && (value[$ - 1] == '\n' || value[$ - 1] == '\r' || value[$ - 1] == ' ' || value[$ - 1] == '\t')) {
		value = value[0 .. $ - 1];
	}
	return value;
}
