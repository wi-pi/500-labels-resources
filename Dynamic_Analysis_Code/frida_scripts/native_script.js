// 0x7006abcec0 libeffect.so!0x6b0ec0
// 0x7006aaabbc libeffect.so!0x69ebbc
// 0x7006aaaad0 libeffect.so!0x69ead0
// 0x7006ab16d4 libeffect.so!0x6a56d4
// 0x7006ab4298 libeffect.so!0x6a8298
// 0x7006872bcc libeffect.so!0x466bcc
// 0x7006871f90 libeffect.so!0x465f90
// 0x70068720f0 libeffect.so!0x4660f0
// 0x74918873b4 libc.so!_ZL15__pthread_startPv+0xd4
// 0x74918240bc libc.so!__start_thread+0x44
// 0x74918872e0 libc.so!_ZL15__pthread_startPv


Java.perform(function() {
    var soName = "libeffect.so";
    var soName2 = "libbytenn.so";
    var soName3 = "libc.so";
    // var offsetWithinSO = ptr("0x30e864");  // replace with your offset
    // var offsetWithinSO = ptr("0xc66e34");
    // var offsetWithinSO = ptr("0x30e82c"); //Interesting strings in registers
    // var offsetWithinSO = ptr("0x6be030"); //bach_face_expression string location
    // var offsetWithinSO = ptr("0xca1478"); //Good one
    // var offsetWithinSO = ptr("0xbbb990"); // boy prob set    
    // var offsetWithinSO = ptr("0xc66894"); // Good
    // var offsetWithinSO = ptr("0xc9ae04");
    // var offsetWithinSO = ptr("0xd08258"); // Only called when face appears on video stream.
    // var offsetWithinSO = ptr("0x9dd9b8"); //Bounding Box hook
    // var offsetWithinSO = ptr("0xc65140"); //Message Handler
    // var offsetWithinSO = ptr("0xbbc518");  // Inference function
    // var offsetWithinSO = ptr("0x991058");  // Batch profile thing
    // var offsetWithinSO = ptr("0xc8d494");  //face detect x8 jump
    // var offsetWithinSO = ptr("0x6bfde8");  //Address for the x8 value setting for the weird function.
    // var offsetWithinSO = ptr("0x322f78");  //Address for the x8 value setting for the weird function.
    // var offsetWithinSO = ptr("0xbbb5a4");  //Address for the x8 value setting for the weird function.
    
    var offsetWithinSO = ptr("0xc6ed84");  //Address for the x8 value setting for the weird function.
    
    // var offsetWithinSO = ptr("0x6b0c80");  //message constructor call


    var offsetWithinSO2 = ptr("0x433a0");  //Address for the x8 value setting for the weird function.
    
    //var offsetWithinSO2 = ptr("0x6c71e0");  //Address for the x8 value setting for the weird function.
    
    var offsetWithinSO3 = ptr("0x9de33c");  //Address for the x8 value setting for the weird function.
    //0xc5a78c
    
    // var offsetWithinSO4 = ptr("0xbbc7fc");  //Address for the x8 value setting for the weird function.
    var offsetWithinSO4 = ptr("0x367454");  //Address for the x8 value setting for the weird function.
    
    
    
    
    // var offsetWithinSO_nn = ptr("0x3df1c");// Inference function
    // var offsetWithinSO_nn = ptr("0x3df54");// x8 branch call in inference function
    // var offsetWithinSO_nn = ptr("0x40c00");// x8 landing from inference
    // var offsetWithinSO_nn = ptr("0x53324");// ML inference bytes hook
    // var offsetWithinSO_nn = ptr("0x2f2b4");// ML inference bytes hook
    // var offsetWithinSO_nn = ptr("0x3e04c");// If statement in extract
    // var offsetWithinSO_nn = ptr("0x8be4");// 
    // var offsetWithinSO_nn = ptr("0x3dfa4") // This is teh extract method. Important beceause its how tiktok gets back the data.
    // var offsetWithinSO_nn = ptr("0xc67c18") // This is teh extract method. Important beceause its how tiktok gets back the data.
    // var offsetWithinSO_nn = ptr("0x282d0") // Init call for engine
     
    // var offsetWithinSO_nn = ptr("0x29288") // Loading some string into memory?
    
    var offsetWithinSO_nn = ptr("0x43448") // Experimenting
    
    // var offsetWithinSO_nn = ptr("0x433a0") // Inference
    
    
    //GAIA
    // var offsetWithinSO_nn = ptr("0x1e340");// 
    
    
    //gaia
    // var offsetWithinSO_gaia = ptr("0x27694"); // Post Message
    
    //alog
    // var offsetWithinSO_gaia = ptr("0x50e0"); //alog_write
    // var offsetWithinSO_gaia = ptr("0x37cc"); //x0 address for memcpy
    // var offsetWithinSO_gaia = ptr("0x8be4"); //Write call
    // var offsetWithinSO_gaia = ptr("0x6214"); //time getting function I think
    // var offsetWithinSO_gaia = ptr("0x41c8"); //function with loging info in it
    // var offsetWithinSO_gaia = ptr("0x6078"); // Weird function
    // var offsetWithinSO_gaia = ptr("0x8d80"); // Function with alog cache file in it.
    
    
    var offsetWithinSO_gaia = ptr("0xb1270"); // Function with alog cache file in it.
    
    
    
    console.log("FINSIHED LOADING");
    
     
    
    
    
    
    // Find base address of the loaded shared library
    var soBaseAddress = Module.findBaseAddress(soName);
    var soBaseAddress2 = Module.findBaseAddress(soName2);
    var soBaseAddress3 = Module.findBaseAddress(soName3);
    if (!soBaseAddress) {
        throw new Error('Failed to find ' + soName);
    }
    
    // Calculate runtime address of the target location
    var targetAddress = soBaseAddress.add(offsetWithinSO);
    var targetAddress1_5 = soBaseAddress.add(offsetWithinSO2);
    var targetAddress1_75 = soBaseAddress.add(offsetWithinSO3);
    var targetAddress1_80 = soBaseAddress.add(offsetWithinSO4);
    
    
    var targetAddress2 = soBaseAddress2.add(offsetWithinSO_nn);
    var targetAddress3 = soBaseAddress3.add(offsetWithinSO_gaia);
    
    
    function printStackTrace(context) {
       
        // Get the call stack
        var stack = Thread.backtrace(context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress)
            .join("\n");
        console.log(stack);
    
    }
    
    
    
    function read_reg(reg, str) {
        var n = 1024;  // Change this to the number of bytes you want to read    
    
        try{
        // Create a buffer from the address in the register
        var buffer = Memory.readByteArray(reg, n);
    
        // Convert the buffer to a string
        var byteString = Array.from(new Uint8Array(buffer))
                             .join(' ');
        console.log(byteString);
        console.log(`Bytes from ${str}:`, byteString);
        }catch(e){
            console.log(reg);
        }
    }
    
    
    function address_check_and_change(addressInX8){
        var isAddressValid = false;
        var originalProtection = null;
    
        // Enumerate all memory ranges to find if addressInX8 is within a valid range.
        var ranges = Process.enumerateRanges('---');
        for (var range of ranges) {
            if (addressInX8.compare(range.base) >= 0 && addressInX8.compare(range.base.add(range.size)) < 0) {
                console.log("Address is in a valid range with protection: " + range.protection);
                isAddressValid = true;
                originalProtection = range.protection;
                break;
            }
        }
    
        if (isAddressValid) {
            // Make the memory region writable.
            Memory.protect(addressInX8, 1, 'rw-');
    
            // Perform your write operation here.
            // For example, to write a single byte value 0xAA:
            Memory.writeU8(addressInX8, 0xAA);
    
            // Restore the original protection.
            Memory.protect(addressInX8, 1, originalProtection);
        } else {
            console.log("Address is not in a valid range.");
        }
    
    }
    
    
    // Attach an interceptor to detect execution
    //.readUtf8String()
    Java.perform(function() {
    Interceptor.attach(targetAddress, {
        onEnter: function(args) {
            // console.log('LIBEFFECT Executed at address:', targetAddress);
            // console.log(this.context.x8 & 0xFFFFFFFF);
            // console.log( args[1].readUtf8String() );
            // console.log( Memory.readByteArray(args[1], 64));
            // var byteArray = Memory.readByteArray(this.context.x1, 64);
            console.log("LIBEFFECT");
            console.log(this.context.x0.add(this.context.x8).readFloat());
            // console.log(this.context.q2);


            // console.log(args[0].readUtf8String(),args[1].readUtf8String());
            // printStackTrace(this.context);
            // console.log(this.context.q1);
            // console.log(this.context.x0);
    
            // var floatArray = logQRegister(this.context.q0);
            // console.log(`q${0}:`, floatArray);
            // var floatArray = logQRegister(this.context.q1);
            // console.log(`q${1}:`, floatArray);
    
    
    
            // console.log(this.context.x15);
    
         
            // console.log(this.context.x9.readFloat());
            // console.log(this.context.x21.add(0x20).readPointer().readFloat());
            // console.log(this.context.x21.add(0x28).readPointer());
    
        
            // console.log(this.context.x0.readPointer().readFloat());
            // var stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
            // var stackTraceString = stackTrace.map(function(st) {
            //     return st.toString();
            // }).join('\n');
            // console.log(`\x1b[31m [+] Current Java Call Stack: \n ${stackTraceString} \x1b[0m` );
            
            // var currentThreadId = Process.getCurrentThreadId();
            // console.log("Function intercepted on thread ID:", currentThreadId);
    
            // console.log(args[1].add(0x18).readInt());
            // this.context.x21 = 0x1;
            // console.log("edited");
            // this.context.x0 = 1;
            // console.log(this.context.x0&1);
            // // // Convert the ByteArray to a String
            // var stringFromMemory = '';
            // var uint8Array = new Uint8Array(byteArray);
    
            // for (var i = 0; i < uint8Array.length; i++) {
            //     stringFromMemory += String.fromCharCode(uint8Array[i]);
            // }
    
            // // Check if the string exists within the memory data
            // if (stringFromMemory.indexOf("beauty") !== -1) {
            //     console.log("String found!");
            //     console.log(byteArray)
            //     printStackTrace.call(this);
            // } else {
            //     // console.log("String not found.");
            // }
    
            // try{
            //     address_check_and_change(this.context.x8);
            // }catch(e){
            //     console.log("Failed to read address.");
            // }
            // read_string(args[0], "arg[0]");
            // read_string(args[1], "arg[1]"); 
            // read_string(args[2], "arg[2]");
            // read_string(args[3], "arg[4]");
            // read_string(args[4], "arg[4]");
            // console.log( (args[0].add(0x671)).readUtf8String() );
            // read_reg(args[0], "arg[0]");
            // read_reg(args[1], "arg[1]");
            // read_reg(args[2], "arg[2]");
            // read_reg(args[3], "arg[3]");
            // read_reg(args[4], "arg[4]");
    
            // Print the s registers
            // for (let i = 0; i <= 31; i++) {
            //     console.log(`s${i}: ${this.context["s" + i]}`);
            // }
    
            // var call_addr = this.context.x1.sub(soBaseAddress);
            // console.log(call_addr);
            // var call_addr2 = this.context.x1.sub(soBaseAddress2);
            // console.log(call_addr2);
            // var call_addr3 = this.context.x1.sub(soBaseAddress3);
            // console.log(call_addr3);
            
            
            // // Print the d registers
            // for (let i = 0; i <= 31; i++) {
            //     console.log(`d${i}: ${this.context["d" + i]}`);
            // }
    
            // // Print the x registers
            // for (let i = 0; i <= 28; i++) {  // Assuming up to x28 as you mentioned in the script
            //     read_reg(this.context["x" + i], `x${i}:`);
            // }
    
            // read_reg(this.context.x4,"x4");
    
            // for (let i = 0; i < 16; i++) { // ARM64 has q0 to q31
            //     // Construct the d register names
            //     let dRegister1 = "d" + (i * 2);
            //     let dRegister2 = "d" + (i * 2 + 1);
    
            //     // Read the values of the two d registers
            //     let part1 = this.context[dRegister1];
            //     let part2 = this.context[dRegister2];
    
            //     console.log(`q${i}:`, part1, part2);
            // }
            
            // var addressToRead = this.context.sp.add(0x08);
    
            // // Define the number of bytes you want to read, for instance 16
            // var numBytes = 128;
    
            // // Read bytes from the address
            // var byteArray = Memory.readByteArray(addressToRead, numBytes);
    
            // // Convert to an array of bytes
            // var byteValues = Array.from(new Uint8Array(byteArray));
    
            // console.log(`Bytes from address ${addressToRead}:`, byteValues);
    
    
            // var funcPointer = this.context.x1;
            // console.log(`${this.context.x1 }`)
            // console.log(`memcpy(${this.context.x1},${args[1].readUtf8String()},${args[2]})` )
            // if(args[1].readUtf8String().includes("") && this.context.x1 != 0x0){
                 // Define the number of bytes you want to read
                //  read_reg(this.context.x0,"x0");
                //  read_reg(this.context.x1,"x1");
                //  read_reg(this.context.x20,"x20");
    
            // }
            // console.log(ptr(call_addr).sub(ptr("0x9dd9b8")))
            // if(ptr(call_addr).sub(ptr("0x9dd9b8")) == 0){
            //     printStackTrace.call(this);
            // }
            
        },
    
        onLeave: function(retval){
            // console.log("LEAVING");
            // console.log(this.context.s8);
            // printStackTrace.call(this);
            // console.log(`RETURNING: ${retval}`);
            // if(retval != 0x0){
            //     // read_reg(retval,"x20");
            //     console.log(this.context.d8)
            // }
           
            // Print the s registers
            // for (let i = 0; i <= 31; i++) {
            //     console.log(`s${i}: ${this.context["s" + i]}`);
            // }
            // console.log(retval);
    
        }
    });
    });
    
    // Interceptor.attach(targetAddress1_5, {
    //     onEnter: function(args) {
    
    //         console.log("LIBEFFECT2");
    
    //         // var exampleFunctionAddress = soBaseAddress.add(ptr("0x846290")); // replace 0xSOME_OFFSET with the appropriate offset
    //         // var getting_something= new NativeFunction(exampleFunctionAddress, 'void', [ 'pointer' ]);
    //         // var beauty_ptr = soBaseAddress.add(ptr("0x1532878"));
    //         // console.log(beauty_ptr.readFloat());
    //         // getting_something(ptr("0x0"));
    
    
    //         // Optional: stop stalking after some time
    //         // setTimeout(function () {
    //         //     Stalker.unfollow(targetThreadId);
    //         //     console.log("Stopped stalking");
    //         // }, 10000); // stops after 10 seconds
    
    
            
            
    //     },
    
    //     onLeave: function(retval){
    //         retval = 0;
    //         console.log(retval);
    
    //     }
    // });
    
    Interceptor.attach(targetAddress1_75, {
        onEnter: function(args) {
    
            console.log("LIBEFFECT3");
            // this.context.x20 = 0x1c;
            // console.log(this.context.x20&0x1c);
    
    
            //  //w8,[x25, #0x590]
            //  var x25 = this.context.x25.add(0x590);
            //  console.log(x25.readInt());
    
            // printStackTrace(this.context);
    
            
        },
    
        onLeave: function(retval){
            console.log(retval);
    
        }
    });
    
    
    Interceptor.attach(targetAddress1_80, {
        onEnter: function(args) {
    
            console.log("LIBEFFECT4");
            // var pointer = Memory.alloc(4);
    
            // // Write a float value to the allocated memory
            // pointer.writeFloat(1.0);
            // this.context.sp.add(0x188).writePointer(pointer);
            // printStackTrace(this.context);
            // console.log(this.context.x8 );
            // console.log(this.context.x8 & 1);
            // console.log(this.context.x8 >> 1);
    
            
        },
    
        onLeave: function(retval){
            console.log(retval);
    
        }
    });
    
    
    var scudo_switch = false;
    
    
    Interceptor.attach(targetAddress2, {
        onEnter: function(args) {
        //     console.log('BYTENN Executed at address:', targetAddress);
        //     // console.log( Memory.readByteArray(args[1], 30));
        //     // console.log(args[1].readUtf8String());
    
        //     var exampleFunctionAddress = soBaseAddress2.add(ptr("0x28958")); // replace 0xSOME_OFFSET with the appropriate offset
        //     var getNetwork = new NativeFunction(exampleFunctionAddress, 'pointer', [ 'pointer']);
        //     var network = args[0].add(0x8).readPointer().readPointer();
           
        //    //condition 1 Good
        //    console.log(network.add(0x46c).readInt()); 
        //    //condition  2 Good
        //    console.log(network.add(0x8).readLong()); 
        //    //condition 3 
        //    console.log(network.add(0x468).readPointer()); 
    
        //    console.log(network.add(0x8).readPointer().readPointer().add(0x30).readPointer().readPointer());     
    
    
    
        //     var model_size = network.add(0x50).readInt();
        //     console.log(model_size);
    
        //     console.log(network.add(0x48).readPointer());
        console.log("LIBNN");
        printStackTrace(this.context);
        // console.log(this.context.x13.sub(soBaseAddress2));
        // console.log(this.context.x1);
        // var floatArray = logQRegister(this.context.q0);
        // console.log(`q${0}:`, this.context.q0);
        // var floatArray = logQRegister(this.context.q1);
        // console.log(`q${1}:`, this.context.q1);
    
        // var bytes = this.context.q3;  // replace with the list of 16 bytes you got
        //     // Allocate a buffer for the 16 bytes
        //     var buffer = Memory.alloc(16);
    
        //     // Write the entire byte array to our buffer
        //     Memory.writeByteArray(buffer, bytes);
    
        //     // Read each of the four floats
        //     var float1 = Memory.readFloat(buffer);
        //     var float2 = Memory.readFloat(ptr(buffer).add(4));
        //     var float3 = Memory.readFloat(ptr(buffer).add(8));
        //     var float4 = Memory.readFloat(ptr(buffer).add(12));
    
        //     // If you want them in an array:
        //     var floatArray = [float1, float2, float3, float4];
    
        //     console.log(floatArray);
        // console.log(Memory.readByteArray(this.context.sp,128),Memory.readByteArray(this.context.sp.add(0x8),128));
        // scudo_switch = true;
        // console.log("CONFIG VALUES");
        // console.log(this.context.x19.add(0x2).readInt());
        // console.log(this.context.x19.add(0x14).readInt());
        // console.log(this.context.x19.add(0x3).readInt());
        // console.log(this.context.x19.add(0x1c).readInt());
        // console.log(this.context.x19.add(0x1).readFloat());
        // console.log(this.context.x19.add(0xc).readFloat());
        // console.log(this.context.x19.add(0x4).readFloat());
    
    
        
        // Replace this with the thread ID you want to trace.
        // var targetThreadId =  Process.getCurrentThreadId(); 
    
        // // Start stalking
        // Stalker.follow(targetThreadId, {
        //     events: {
        //         call: true,   // capture calls
        //         ret: false,   // capture returns
        //         exec: false   // capture individual instructions
        //     },
        //     onReceive: function (events) {
        //         var instructions = Stalker.parse(events);
        //         for (var i = 0; i < instructions.length; i++) {
        //             var instruction = instructions[i];
        //             console.log(instruction);
        //         }
        //     },
        //     onCallSummary: function (summary) {
        //         for (var address in summary) {
        //             var addr_ptr = ptr(address);
        //             console.log(addr_ptr.sub(soBaseAddress), "was called", summary[address], "times");
        //         }
        //     }
        // });
    
        // setTimeout(function () {
        //     Stalker.unfollow(targetThreadId);
        //     console.log("Stopped stalking thread:", targetThreadId);
        // }, 1000);
    
        },
    
        onLeave: function(retval){
            scudo_switch = false;
            console.log(`RET = ${retval}`);
            // Assuming there's a way to get the q register context by index or name:
            // for (let i = 0; i < 32; i++) {
            //     var bytes = this.context["q" + i];  // Get bytes for the q register
            //     var floatArray = logQRegister(bytes);
            //     console.log(`q${i}:`, floatArray);
            // }
    
    
        }
    });
    
    function readlink(fd) {
        var bufferSize = 4096;
        var buf = Memory.alloc(bufferSize);
        var path = "/proc/self/fd/" + fd;
    
        // Call the readlink function
        var result = new NativeFunction(Module.findExportByName(null, 'readlink'), 'int', ['pointer', 'pointer', 'size_t']);
        var bytesWritten = result(Memory.allocUtf8String(path), buf, bufferSize - 1);
    
        if (bytesWritten === -1) {
            return path; // or throw an error, based on your preference
        }
    
        // Convert the result into a JavaScript string
        return buf.readUtf8String(bytesWritten);
    }
    
    function read_string(reg,string){
        try{
            console.log(string + ": " + reg.readUtf8String());
        }catch(e){
            console.log(e);
            console.log(string);
        }
    }
    
    // Function to read and log the contents of a single q register
    function logQRegister(bytes) {
        // Allocate a buffer for the 16 bytes
        var buffer = Memory.alloc(16);
    
        // Write the entire byte array to our buffer
        Memory.writeByteArray(buffer, bytes);
    
        // Read each of the four floats
        var float1 = Memory.readFloat(buffer);
        var float2 = Memory.readFloat(ptr(buffer).add(4));
        var float3 = Memory.readFloat(ptr(buffer).add(8));
        var float4 = Memory.readFloat(ptr(buffer).add(12));
    
        // Return them in an array:
        return [float1, float2, float3, float4];
    }
    
    // Function to read and log the contents of a single q register
    function logQRegister_int8(bytes) {
        // Allocate a buffer for the 16 bytes
        var buffer = Memory.alloc(16);
    
        // Write the entire byte array to our buffer
        Memory.writeByteArray(buffer, bytes);
        var array = []; 
        // Read each of the four floats
        for (var i =0; i < 16; i++){
            var float1 = Memory.readS8(buffer.add(i));
            array.push(float1);
        }
        // Return them in an array:
        return array
    }
    
    // Function to read and log the contents of a single q register
    function logQRegister_int16(bytes) {
        // Allocate a buffer for the 16 bytes
        var buffer = Memory.alloc(16);
    
        // Write the entire byte array to our buffer
        Memory.writeByteArray(buffer, bytes);
        var array = []; 
        // Read each of the four floats
        for (var i =0; i < 8; i+=2){
            var float1 = Memory.readS16(buffer.add(i));
            array.push(float1);
        }
        // Return them in an array:
        return array
    }
    
    // Function to read and log the contents of a single q register
    function logQRegister_int32(bytes) {
        // Allocate a buffer for the 16 bytes
        var buffer = Memory.alloc(16);
    
        // Write the entire byte array to our buffer
        Memory.writeByteArray(buffer, bytes);
        var array = []; 
        // Read each of the four floats
        for (var i =0; i < 4; i+=4){
            var float1 = Memory.readS16(buffer.add(i));
            array.push(float1);
        }
        // Return them in an array:
        return array
    }
    
    
    // Function to read and log the contents of a single q register
    function logQRegister_int64(bytes) {
        // Allocate a buffer for the 16 bytes
        var buffer = Memory.alloc(16);
    
        // Write the entire byte array to our buffer
        Memory.writeByteArray(buffer, bytes);
        var array = []; 
        // Read each of the four floats
        for (var i =0; i < 2; i+=8){
            var float1 = Memory.readS16(buffer.add(i));
            array.push(float1);
        }
        // Return them in an array:
        return array
    }
    
    
    // Function to read and log the contents of a single q register
    function logQRegister_int3(bytes) {
        // Allocate a buffer for the 16 bytes
        var buffer = Memory.alloc(16);
    
        // Write the entire byte array to our buffer
        Memory.writeByteArray(buffer, bytes);
        var array = []; 
        // Read each of the four floats
        for (var i =0; i < 8; i+=2){
            var float1 = Memory.readS16(buffer.add(i));
            array.push(float1);
        }
        // Return them in an array:
        return array
    }
    
    
    function address_dive(reg){
        try{
            address_dive(reg.readPointer());
        }catch(e){
            console.log(reg);
            // console.log( `Float64: ${bigIntToFloat64(BigInt(reg))}` );
            console.log( `Float32: ${reg}` );
    
            // try{
            // console.log(reg.readUtf8String());
            // }catch(e){
            //     readAndDisplayMemory(reg,256);
            // }
        }
    }
    
    Java.perform(function(){ 
    Interceptor.attach(targetAddress3, {
        onEnter: function(args) {
            // console.log("PTHREAD");
            // // printStackTrace(this.context);
            // var stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
            // var stackTraceString = stackTrace.map(function(st) {
            //     return st.toString();
            // }).join('\n');
            // console.log(`\x1b[31m [+] Current Java Call Stack: \n ${stackTraceString} \x1b[0m` );
        },
    
        onLeave: function(retval){
            
    
        }
    });
    });
    
    
    });