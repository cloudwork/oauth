exports.testOAuth = require("./oauth-tests");

if (require.main === module.id)
    require("test/runner").run(exports);
