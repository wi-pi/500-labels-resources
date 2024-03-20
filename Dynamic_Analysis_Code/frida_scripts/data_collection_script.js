setTimeout(function () {
    /* your code here */
Java.perform(function() {

    var File = Java.use("java.io.File");
     var Arrays = Java.use("java.util.Arrays");
     var BitmapFactory = Java.use('android.graphics.BitmapFactory');
 
 
     
 
     function listFilesRecursive(file) {
         var paths = [];
         if (file.isDirectory()) {
             var files = file.listFiles();
             if (files !== null) {
                 var fileList = Arrays.asList(files);
                 for (var i = 0; i < fileList.size(); i++) {
                     var subFile = Java.cast(fileList.get(i),Java.use("java.io.File"));
                     if (subFile.isDirectory()) {
                         paths = paths.concat(listFilesRecursive(subFile));
                     } else {
                         if (subFile.getAbsolutePath().toString().match(/\.(jpg|jpeg|png|gif|bmp)$/i)) {
                             paths.push(subFile.getAbsolutePath().toString());
                         }
                     }
                 }
             }
         }
         return paths;
     }
 
     var externalStorageDir = Java.use('android.os.Environment').getExternalStorageDirectory().toString();
 
     var directoriesToCheck = ['DCIM', 'Pictures', 'Downloads'];  // Add more directories if needed
 
     var imagePaths = [];

     var bitmaps = [];
    //  for (var i = 0; i < directoriesToCheck.length; i++) {
       
    //      var dirPath = externalStorageDir + '/' + directoriesToCheck[i];
    //      var dir = File.$new(dirPath);  // Use $new to instantiate Java objects in Frida
    //      var tmp = listFilesRecursive(dir);
    //     //  console.log(tmp);
    //      if(tmp != null && tmp != undefined){
    //         for (var j = 0; j < tmp.length; j++) {
    //             imagePaths.push(tmp[j]);
    //             // console.log(imagePaths)
    //         }
    //      }else{
    //         continue
    //      }
        
         
    //  }

    //  if(imagePaths != null){
    //     for (var j = 0; j < imagePaths.length; j++) {
    //         var path = imagePaths[j];
    //         // console.log(path);
    //         if (path != undefined && path != null){
    //             var bitmap = Java.cast(BitmapFactory.decodeFile(path), Java.use("android.graphics.Bitmap")) ;
    //             // console.log("Created bitmap for: " + path);
    //             bitmaps.push(bitmap);
    //         }
    //     }
    //  }
 
    //  console.log(bitmaps);
 
     console.log("READY");
 
     var thread_class = Java.use('X.80q');
     var debug_class = Java.use('X.0dM');
 
     thread_class.invokeSuspend.implementation = function(k33){
         //Get return of the invoke suspend function.
         console.log(this.A03.value);
         //Checks to see if the current instance is the ML case.
         if(this.A03.value == 5){
                
                for (var i = 0; i < directoriesToCheck.length; i++) {
       
                    var dirPath = externalStorageDir + '/' + directoriesToCheck[i];
                    var dir = File.$new(dirPath);  // Use $new to instantiate Java objects in Frida
                    var tmp = listFilesRecursive(dir);
                   //  console.log(tmp);
                    if(tmp != null && tmp != undefined){
                       for (var j = 0; j < tmp.length; j++) {
                           var imagePath = tmp[j]; 
                           console.log(imagePath)

                           var bitmap = Java.cast(BitmapFactory.decodeFile(imagePath), Java.use("android.graphics.Bitmap")) ;
                            var clips_xray_obj = Java.cast(this.A02.value,Java.use("com.instagram.ml.clipsxray.ClipsXRayVisualFeatureExtractor"))
                
                            //  for(let i=0; i < bitmaps.length; i+=1){
                
                            var thing_7QR = Java.cast(clips_xray_obj.A01.value, Java.use("X.7QR"));

                            
                            var thing_7OB = Java.use("X.EA4").$new(bitmap);

                            var list_thing = Java.use("java.util.Collections").singletonList(thing_7OB);
                        
                            var thing_G7o =  Java.use("X.7QR").A00(thing_7QR,list_thing);
                            

                            var list_thing2 = Java.cast(thing_G7o,Java.use("X.EAF")).A00.value;
                            
                            var ret_string = "";
                            for(var k=0; k < list_thing2.size();k++){
                                var thing_7x6 = Java.cast(list_thing2.get(k),Java.use("X.8Ll"));
                                ret_string+= `${thing_7x6.A01.value},${thing_7x6.A00.value}\t`;
                            }
                            console.log(ret_string);
                       }
                    }
                
             }
             
            //  var clips_xray_obj = Java.cast(this.A02.value,Java.use("com.instagram.ml.clipsxray.ClipsXRayVisualFeatureExtractor"))
             
            // //  for(let i=0; i < bitmaps.length; i+=1){
            //     var ret_string = "";
            //    console.log(`${imagePaths[i]}`);
 
            //    var thing_7QR = Java.cast(clips_xray_obj.A01.value, Java.use("X.7QR"));

               
            //    var thing_7OB = Java.use("X.EA4").$new(bitmaps[i]);

            //    var list_thing = Java.use("java.util.Collections").singletonList(thing_7OB);

            // //    console.log(list_thing.get(0));
        
            //    var thing_G7o =  Java.use("X.7QR").A00(thing_7QR,list_thing);
               

            //    var list_thing2 = Java.cast(thing_G7o,Java.use("X.EAF")).A00.value;
               
            //    for(var j=0; j < list_thing2.size();j++){
            //     var thing_7x6 = Java.cast(list_thing2.get(j),Java.use("X.8Ll"));
            //     ret_string+= `${thing_7x6.A01.value},${thing_7x6.A00.value}\t`;
            //    }

            //    console.log(ret_string);
 
        //    }
             // var obj_0bA = Java.cast(this.A03.value,Java.use("X.0bA"));
             // var obj_6YZ = Java.cast(obj_0bA.getValue(), Java.use("X.6YZ"));
 
         }
         console.log("DONE");
         var ret = this.invokeSuspend(k33);

         return ret;
     };
     
 });

}, 0);