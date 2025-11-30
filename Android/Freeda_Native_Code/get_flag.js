
Java.perform(function () {
  var addr = Process.getModuleByName('libv3.so').findExportByName('check_root'); 
  Interceptor.replace(addr, new NativeCallback(function () {
    return 1; // OK
  }, "int", []));
  console.log("[+] Root device set to false")

  var addr = Process.getModuleByName('libv3.so').findExportByName('get_flag'); 
  var getFlag = new NativeFunction(ptr(addr), 'pointer', []); 
  var p = getFlag(); 
  console.log("[+]",p.readCString());

});


