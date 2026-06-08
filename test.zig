const std = @import("std");
const oauth2 = @import("oauth2");
const nio = @import("nio");
const http = @import("http");
const json = @import("json");

test {
    _ = &oauth2.Provider;
    _ = &oauth2.Client;
    std.testing.refAllDecls(oauth2.providers);
    std.testing.refAllDecls(oauth2.dynamic_providers);
    _ = &oauth2.providerById;
    _ = &oauth2.clientByProviderId;
    _ = &oauth2.pek_domain;
}
test {
    const S = struct {
        pub const callbackPath = "/-/callback";
        pub const doneUrl = "/";

        pub fn isLoggedIn(_: *http.ServerRequest, _: std.mem.Allocator) !bool {
            return false;
        }
        pub fn saveInfo(_: *http.HeadersMap, _: std.mem.Allocator, _: oauth2.Provider, _: []const u8, _: []const u8, _: json.Document, _: json.Document) !void {
            //
        }
    };
    const H = oauth2.Handlers(S);
    std.testing.refAllDecls(oauth2.Handlers(S));
    _ = @TypeOf(H.login(undefined, nio.NullWriter{}, undefined, undefined, undefined, undefined, undefined));
    _ = @TypeOf(H.callback(undefined, nio.NullWriter{}, undefined, undefined, undefined, undefined, undefined));
}
