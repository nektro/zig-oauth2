const std = @import("std");
const oauth2 = @import("oauth2");

// TODO: how do we make this better?
test {
    std.testing.refAllDeclsRecursive(oauth2);
}
