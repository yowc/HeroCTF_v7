Java.perform(function () {

  // anti-root bypass
  var Sec = Java.use('com.heroctf.freeda2.utils.Security');
  Sec.detectRoot.overload('android.content.Context').implementation = function (ctx) {
    return false;
  };

  // get the flag
  var Vault = Java.use('com.heroctf.freeda2.utils.Vault');
  var flag = Vault.get_flag();
  console.log('[FLAG] ' + flag);
});
