//! https://oauth.net/2/

const std = @import("std");
const string = []const u8;
const http = @import("apple_pie");
const files = @import("self/files");
const pek = @import("pek");
const uri = @import("uri");
const zfetch = @import("zfetch");
const json = @import("json");
const extras = @import("extras");
const Base = @This();

pub const Provider = struct {
    id: string,
    authorize_url: string,
    token_url: string,
    me_url: string,
    scope: string = "",
    name_prop: string,
    name_prefix: string = "",
    id_prop: string = "id",
    logo: string,
    color: string,

    pub fn domain(self: Provider) string {
        if (std.mem.indexOfScalar(u8, self.id, ',')) |_| {
            var iter = std.mem.split(u8, self.id, ",");
            _ = iter.next();
            return iter.next().?;
        }
        return self.id;
    }
};

pub const Client = struct {
    provider: Provider,
    id: string,
    secret: string,
};

fn icon_url(comptime name: string) string {
    return "https://unpkg.com/simple-icons@" ++ "5.13.0" ++ "/icons/" ++ name ++ ".svg";
}

pub const providers = struct {
    pub var amazon = Provider{
        .id = "amazon",
        .authorize_url = "https://www.amazon.com/ap/oa",
        .token_url = "https://api.amazon.com/auth/o2/token",
        .me_url = "https://api.amazon.com/user/profile",
        .scope = "profile",
        .name_prop = "name",
        .id_prop = "user_id",
        .logo = icon_url("amazon"),
        .color = "#FF9900",
    };
    pub var battle_net = Provider{
        .id = "battle.net",
        .authorize_url = "https://us.battle.net/oauth/authorize",
        .token_url = "https://us.battle.net/oauth/token",
        .me_url = "https://us.battle.net/oauth/userinfo",
        .scope = "openid",
        .name_prop = "battletag",
        .logo = icon_url("battle-dot-net"),
        .color = "#00AEFF",
    };
    pub var discord = Provider{
        .id = "discord",
        .authorize_url = "https://discordapp.com/api/oauth2/authorize",
        .token_url = "https://discordapp.com/api/oauth2/token",
        .me_url = "https://discordapp.com/api/users/@me",
        .scope = "identify",
        .name_prop = "username",
        .name_prefix = "@",
        .logo = icon_url("discord"),
        .color = "#7289DA",
    };
    pub var facebook = Provider{
        .id = "facebook",
        .authorize_url = "https://graph.facebook.com/oauth/authorize",
        .token_url = "https://graph.facebook.com/oauth/access_token",
        .me_url = "https://graph.facebook.com/me",
        .name_prop = "name",
        .logo = icon_url("facebook"),
        .color = "#1877F2",
    };
    pub var github = Provider{
        .id = "github",
        .authorize_url = "https://github.com/login/oauth/authorize",
        .token_url = "https://github.com/login/oauth/access_token",
        .me_url = "https://api.github.com/user",
        .scope = "read:user",
        .name_prop = "login",
        .name_prefix = "@",
        .logo = icon_url("github"),
        .color = "#181717",
    };
    pub var google = Provider{
        .id = "google",
        .authorize_url = "https://accounts.google.com/o/oauth2/v2/auth",
        .token_url = "https://www.googleapis.com/oauth2/v4/token",
        .me_url = "https://www.googleapis.com/oauth2/v1/userinfo?alt=json",
        .scope = "profile",
        .name_prop = "name",
        .logo = icon_url("google"),
        .color = "#4285F4",
    };
    pub var microsoft = Provider{
        .id = "microsoft",
        .authorize_url = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        .token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        .me_url = "https://graph.microsoft.com/v1.0/me/",
        .scope = "https://graph.microsoft.com/user.read",
        .name_prop = "displayName",
        .logo = icon_url("microsoft"),
        .color = "#666666",
    };
    pub var reddit = Provider{
        .id = "reddit",
        .authorize_url = "https://old.reddit.com/api/v1/authorize",
        .token_url = "https://old.reddit.com/api/v1/access_token",
        .me_url = "https://oauth.reddit.com/api/v1/me",
        .scope = "identity",
        .name_prop = "name",
        .name_prefix = "u/",
        .logo = icon_url("reddit"),
        .color = "#FF4500",
    };
};

pub const dynamic_providers = struct {
    pub const _gitea = Provider{
        .id = "gitea",
        .authorize_url = "https://{[domain]s}/login/oauth/authorize",
        .token_url = "https://{[domain]s}/login/oauth/access_token",
        .me_url = "https://{[domain]s}/api/v1/user",
        .name_prop = "username",
        .name_prefix = "@",
        .logo = icon_url("gitea"),
        .color = "#609926",
    };
    pub const _gitlab = Provider{
        .id = "gitlab",
        .authorize_url = "https://{[domain]s}/oauth/authorize",
        .token_url = "https://{[domain]s}/oauth/token",
        .me_url = "https://{[domain]s}/api/v4/user",
        .scope = "read_user",
        .name_prop = "username",
        .name_prefix = "@",
        .logo = icon_url("gitlab"),
        .color = "#FCA121",
    };
    pub const _mastodon = Provider{
        .id = "mastodon",
        .authorize_url = "https://{[domain]s}/oauth/authorize",
        .token_url = "https://{[domain]s}/oauth/token",
        .me_url = "https://{[domain]s}/api/v1/accounts/verify_credentials",
        .scope = "read:accounts",
        .name_prop = "username",
        .name_prefix = "@",
        .logo = icon_url("mastodon"),
        .color = "#3088D4",
    };
    pub const _pleroma = Provider{
        .id = "pleroma",
        .authorize_url = "https://{[domain]s}/oauth/authorize",
        .token_url = "https://{[domain]s}/oauth/token",
        .me_url = "https://{[domain]s}/api/v1/accounts/verify_credentials",
        .scope = "read:accounts",
        .name_prop = "username",
        .name_prefix = "@",
        .logo = icon_url("pleroma"),
        .color = "#FBA457",
    };
};

pub fn providerById(alloc: std.mem.Allocator, name: string) !?Provider {
    inline for (std.meta.declarations(providers)) |item| {
        const p = @field(providers, item.name);
        if (std.mem.eql(u8, p.id, name)) {
            return p;
        }
    }
    const c_ind = std.mem.indexOfScalar(u8, name, ',') orelse return null;
    const p_id = name[0..c_ind];
    const domain = name[c_ind + 1 ..];
    const args = .{ .domain = domain };
    inline for (std.meta.declarations(dynamic_providers)) |item| {
        const didp = @field(dynamic_providers, item.name);
        if (std.mem.eql(u8, didp.id, p_id)) {
            return Provider{
                .id = name,
                .authorize_url = try std.fmt.allocPrint(alloc, didp.authorize_url, args),
                .token_url = try std.fmt.allocPrint(alloc, didp.token_url, args),
                .me_url = try std.fmt.allocPrint(alloc, didp.me_url, args),
                .scope = didp.scope,
                .name_prop = didp.name_prop,
                .name_prefix = didp.name_prefix,
                .id_prop = didp.id_prop,
                .logo = didp.logo,
                .color = didp.color,
            };
        }
    }
    return null;
}

pub fn clientByProviderId(clients: []const Client, name: string) ?Client {
    for (clients) |item| {
        if (std.mem.eql(u8, name, item.provider.id)) {
            return item;
        }
    }
    return null;
}

pub const IsLoggedInFn = fn (http.Request) anyerror!bool;

pub fn Handlers(comptime T: type) type {
    comptime std.debug.assert(@hasDecl(T, "Ctx"));
    comptime std.debug.assert(@hasDecl(T, "isLoggedIn"));
    comptime std.debug.assert(@hasDecl(T, "doneUrl"));
    comptime std.debug.assert(@hasDecl(T, "saveInfo"));

    return struct {
        const Self = @This();
        pub var clients: []Client = &.{};
        pub var callbackPath: string = "";

        pub fn login(_: T.Ctx, response: *http.Response, request: http.Request, args: struct {}) !void {
            _ = args;

            const alloc = request.arena;
            const query = try request.context.url.queryParameters(alloc);

            if (query.get("with")) |with| {
                const client = clientByProviderId(Self.clients, with) orelse return try fail(response, "Client with that ID not found!\n", .{});
                return try loginOne(response, request, T, client, Self.callbackPath);
            }

            if (Self.clients.len == 1) {
                return try loginOne(response, request, T, clients[0], Self.callbackPath);
            }

            try response.headers.put("Content-Type", "text/html");
            const page = files.@"/selector.pek";
            const tmpl = comptime pek.parse(page);
            try pek.compile(Base, alloc, response.writer(), tmpl, .{
                .clients = Self.clients,
            });
        }

        pub fn callback(_: T.Ctx, response: *http.Response, request: http.Request, args: struct {}) !void {
            _ = args;

            const alloc = request.arena;
            const query = try request.context.url.queryParameters(alloc);

            const state = query.get("state") orelse return try fail(response, "", .{});
            const client = clientByProviderId(Self.clients, state) orelse return try fail(response, "error: No handler found for provider: {s}\n", .{state});
            const code = query.get("code") orelse return try fail(response, "", .{});

            var params = UrlValues.init(alloc);
            try params.add("client_id", client.id);
            try params.add("client_secret", client.secret);
            try params.add("grant_type", "authorization_code");
            try params.add("code", code);
            try params.add("redirect_uri", try redirectUri(alloc, request, callbackPath));
            try params.add("state", "none");

            const req = try zfetch.Request.init(alloc, client.provider.token_url, null);

            var headers = zfetch.Headers.init(alloc);
            try headers.appendValue("Content-Type", "application/x-www-form-urlencoded");
            try headers.appendValue("Authorization", try std.fmt.allocPrint(alloc, "Basic {s}", .{try extras.base64EncodeAlloc(alloc, try std.mem.join(alloc, ":", &.{ client.id, client.secret }))}));
            try headers.appendValue("Accept", "application/json");

            // TODO print error message to response if this fails
            try req.do(.POST, headers, try params.encode());
            const r = req.reader();
            const body_content = try r.readAllAlloc(alloc, 1024 * 1024 * 5);
            const val = try json.parse(alloc, body_content);

            const at = val.get("access_token") orelse return try fail(response, "Identity Provider Login Error!\n{s}", .{body_content});

            const req2 = try zfetch.Request.init(alloc, client.provider.me_url, null);
            var headers2 = zfetch.Headers.init(alloc);
            try headers2.appendValue("Authorization", try std.fmt.allocPrint(alloc, "Bearer {s}", .{at.String}));
            try headers2.appendValue("Accept", "application/json");

            // TODO print error message if this fails
            try req2.do(.GET, headers2, null);
            const r2 = req2.reader();
            const body_content2 = try r2.readAllAlloc(alloc, 1024 * 1024 * 5);
            const val2 = try json.parse(alloc, body_content2);

            const id = try fixId(alloc, val2.get(client.provider.id_prop).?);
            const name = val2.get(client.provider.name_prop).?.String;
            try T.saveInfo(response, request, client.provider, id, name, val, val2);

            try response.headers.put("Location", T.doneUrl);
            try response.writeHeader(.found);
        }
    };
}

fn loginOne(response: *http.Response, request: http.Request, comptime T: type, client: Client, callbackPath: string) !void {
    if (try T.isLoggedIn(request)) {
        try response.headers.put("Location", T.doneUrl);
    } else {
        const alloc = request.arena;
        const idp = client.provider;
        var params = UrlValues.init(alloc);
        try params.add("client_id", client.id);
        try params.add("redirect_uri", try redirectUri(alloc, request, callbackPath));
        try params.add("response_type", "code");
        try params.add("scope", idp.scope);
        try params.add("duration", "temporary");
        try params.add("state", idp.id);
        const authurl = try std.mem.join(alloc, "?", &.{ idp.authorize_url, try params.encode() });
        try response.headers.put("Location", authurl);
    }
    try response.writeHeader(.found);
}

fn fail(response: *http.Response, comptime err: string, args: anytype) !void {
    try response.writeHeader(.bad_request);
    try response.writer().print(err, args);
}

fn redirectUri(alloc: std.mem.Allocator, request: http.Request, callbackPath: string) !string {
    return try std.fmt.allocPrint(alloc, "http://{s}{s}", .{ request.host().?, callbackPath });
}

fn fixId(alloc: std.mem.Allocator, id: json.Value) !string {
    return switch (id) {
        .String => |v| return v,
        .Int => |v| return try std.fmt.allocPrint(alloc, "{d}", .{v}),
        .Float => |v| return try std.fmt.allocPrint(alloc, "{d}", .{v}),
        else => unreachable,
    };
}

//
//

// TODO make this its own library
const UrlValues = struct {
    inner: std.StringArrayHashMap(string),

    pub fn init(alloc: std.mem.Allocator) UrlValues {
        return .{
            .inner = std.StringArrayHashMap(string).init(alloc),
        };
    }

    pub fn add(self: *UrlValues, key: string, value: string) !void {
        try self.inner.putNoClobber(key, value);
    }

    pub fn encode(self: UrlValues) !string {
        const alloc = self.inner.allocator;
        var list = std.ArrayList(u8).init(alloc);
        var iter = self.inner.iterator();
        var i: usize = 0;
        while (iter.next()) |entry| : (i += 1) {
            if (i > 0) try list.writer().writeAll("&");
            try list.writer().print("{s}={s}", .{ entry.key_ptr.*, uri.escapeString(alloc, entry.value_ptr.*) });
        }
        return list.toOwnedSlice();
    }
};
