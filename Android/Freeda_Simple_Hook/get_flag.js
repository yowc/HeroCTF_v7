Java.perform(function () {
    console.log("START")
    var Vault = Java.use('com.heroctf.freeda1.utils.Vault');
    var flag = Vault.get_flag();
    console.log('[FLAG] ' + flag);
  }
);
