import sys
import re
import sqlite3
import base64
import multiprocessing as mp
import multiprocessing as mp
from multiprocessing import Pool, Manager, Process, Queue, Pipe

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'



use_db = False
display_output = True
preform_comparisons = False
key_words = [ "" ]
preform_comparisons = False
key_words = [ "" ]

# db = sqlite3.connect('V1_long_analysis.db',check_same_thread=False)

caller, worker = Pipe()

do_dynamic_compare = False
dynamic_compare = {}
# functions_of_interest = [ "enrollment","nativeAdd","hotword","audio"]
max_data = 1000

caller, worker = Pipe()

do_dynamic_compare = False
dynamic_compare = {}
# functions_of_interest = [ "enrollment","nativeAdd","hotword","audio"]
max_data = 1000

# cur = db.cursor()
# cur.execute('''CREATE TABLE IF NOT EXISTS Data(
#                     ID INTEGER PRIMARY KEY AUTOINCREMENT,
#                     host TEXT, name TEXT, 
#                     time TEXT,  bytes BLOB,
#                     pid INT, tid INT, 
#                     iArg TEXT,   fArg TEXT,
#                     isret INT
#                     )''')
# cur.execute('''CREATE TABLE IF NOT EXISTS Audio(
#                     host TEXT, time TEXT,
#                     frames INT, bytes BLOB 
#                     )''')

def decode_base64(data, altchars=b'+/'):
    """Decode base64, padding being optional.

    :param data: Base64 data as an ASCII byte string
    :returns: The decoded byte string.

    """
    data = re.sub(rb'[^a-zA-Z0-9%s]+' % altchars, b'', data)  # normalize
    missing_padding = len(data) % 4
    if missing_padding:
        data += b'='* (4 - missing_padding)
    return base64.b64decode(data, altchars)


def parse_line(line):
    
    #Regex string
    regex_string = ".*[0-9][0-9] [0-9][0-9] [0-9][0-9].*" #No zeros
    regex_string2 = ".*[0-9] [0-9] [0-9].*" #More zeros with chacters being less than 3
    regex_string3 = r".*[0-9][0-9]  [0-9][0-9]  [0-9][0-9].* " #More zeros with chacters being less than 3
    ts_regex = "[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]" #Time stamp regex
    tid_regex = r"^[0-9]{2}$|^[0-9]{3}$|^[0-9]{4}$|^[0-9]{5}$|^[0-9]{6}$"

    
    line = line.replace("JACK LOG: INVOKING","")
    line = line.replace("Data","\t")
    
    if "CONT." in line:
        d1,d2 = line.split("CONT.")
        host = line.split("JACK LOG:")[0]
        d1 = d1.split("JACK LOG:")[1]

        split = "\t".join([d1]+[d2])
        split = split.split("\t")
    
    if "turing" in line:
        split = line.split(" : ")
    else:
        #Splits data into parts
        split = line.split("\t")

    #Logcat header information
    meta_info = split[0].strip().split(" ")

    ts = ""
    tid = -1
    pid = -1
    #Get time stamp
    for i in meta_info:
        if re.match(ts_regex, i) != None:
            ts = i
        if pid == -1 and re.match(tid_regex, i) != None:
            pid = int(i)
        elif tid == -1 and re.match(tid_regex, i) != None:
            tid = int(i)

        

    #Name of app that call was made from
    if "CONT." in line:
        pass
    else:
        host = meta_info[-1]

    #Init variable.
    b_array = ""

    #Name of function
    if "CONT." in line:
        fname = split[0]
    elif "JACK FIELDS LOG:" in line:
        fname = split[0].replace("JACK FIELDS LOG:","")
        line = line.replace("Data at","")
    elif "turing" in line or "Always Sunny:":
        fname = "None"
        line = line.lower()
        # print(line)
    else:
        fname = split[1].replace("JACK LOG: INVOKING","")

    entries = []
    
    iot = ''
    fot= ''

    if "CONT." in line or "JNIGENE" in line or "JACK FIELDS" or "turing" in line or "always sunny" in line:
        # print(split)
        start_ind = 0 
        # if "turing" in line:
        #     print(f"LINE={line},SPLIT={split}")
    else:
        start_ind = 5

    first_arr = True
    #Checks if element is a bytes element
    for i in range(start_ind, len(split)):
        # if "turing" in line:
        #     print(f"turing: {split[i]}")
        
        ele = split[i]
        num_arr = []
        extra_data = False
            

        if re.match(regex_string, ele) != None or re.match(regex_string2, ele) != None or re.match(regex_string3, ele) != None:

            
            if "Ret" in split[i]:
                isret = 1
            else:
                isret = 0

            if "turing" in line or "always sunny:" in line:
                # print(f"turing: ele={ele}")
                # if "always sunny" in line:
                #     print(f"SUNNY LINE: {line}")
                tmp_splt = ele
            else:
                tmp_splt= ele.split(":")
            
            
            if len(tmp_splt) < 2 and "turing" not in line and "always sunny:" not in line:
                extra_data = True
                bs_t = tmp_splt[0].strip()
            elif "turing" in line or "always sunny:" in line:
                bs_t = ele.replace("\n","").replace("\t","").split(":")[-1]
            else:
                bs_t = tmp_splt[1].strip()
            
            bs = bs_t.split(" ")
            
            j=0
            while j < len(bs):
                if bs[j] == '':
                    del bs[j]
                else:
                    j+=1
            
            # print(bs)
            for b in bs:
                try:
                    num_arr.append(int(b,16))
                except Exception as e:
                    print(e)


            b_array = bytes(num_arr)
            # if "turing" in line:
            #     print(f"turing barray = {b_array}")

            # if "classifyNative" in line and "Ret" not in line:
            #     with open("raw_bytes_capture","ab") as f:
            #         f.write(b_array[12:])
            
            # if "nativeDecodeByteArray" in line and first_arr:
            #     first_arr = False
            #     with open("raw_bytes_capture","ab") as f:
            #         f.write(b_array[12:])
            
            # if "GETTING DIRECT BUFFER ADDY:" in line and "aoapp.musicall" in line:
            #     with open("raw_bytes_capture_direct_buffer","ab") as f:
            #         f.write(b_array[:16])

            # if "nativecrypt" in line.lower():
            #     with open("raw_bytes_crypt","ab") as f:
            #         f.write(b_array)
            
            # if "hbox:interacto" in line.lower():
            #     with open("raw_bytes_goog","ab") as f:
            #         f.write(b_array)
            
            if extra_data:
                split[i] = bcolors.WARNING + f"LONG IS ON HEAP EXTRA DATA:" + str(b_array) + bcolors.ENDC 
            else:
                if isret:
                    split[i] = bcolors.WARNING+f"Ret: " + str(b_array) + bcolors.ENDC
                elif "turing" in line:
                    split[i] = "HASH RESULTS: " + bcolors.WARNING + str(b_array) + bcolors.ENDC
                elif "always sunny:" in line and "2 always sunny" not in line and "3 always sunny" not in line and "4 always sunny" not in line:
                    split[i] = "HMAC UPDATE: " + bcolors.WARNING + str(b_array) + bcolors.ENDC
                elif "2 always sunny:" in line:
                    split[i] = line.split("2 always sunny:")[0]+" EVP UPDATE: " + bcolors.WARNING + str(b_array) + bcolors.ENDC
                elif "3 always sunny:" in line:
                    split[i] = line.split("3 always sunny:")[0]+" SSL DECRYPT: " + bcolors.WARNING + str(b_array) + bcolors.ENDC
                elif "4 always sunny:" in line:
                    split[i] = line.split("4 always sunny:")[0]+" SSL ENCRYPT: " + bcolors.WARNING + str(b_array) + bcolors.ENDC    
                else:
                    split[i] = bcolors.WARNING+f"ARG {i}: " + str(b_array) + bcolors.ENDC 
            
            entries.append( (host,fname,ts,b_array,pid,tid,iot,fot,isret) )
            b_array = None
        else:
            if ":" in ele and "NULL" not in ele and ele != '':
                if "Ret" in split[i]:
                    isret = 1
                else:
                    isret = 0

                ot = ele.split(":")[1].strip()
                if ot != '' and ot.lower() != 'nan' and ot.lower() != 'inf':
                    if "." in ot:
                        fot = ot
                        entries.append( (host,fname,ts,b_array,pid,tid,iot,fot,isret) )
                        fot = ''
                    else:
                        iot = ot
                        entries.append( (host,fname,ts,b_array,pid,tid,iot,fot,isret) )
                        iot = ''
    
    ret = "\t".join(split)
    
    return ret,entries

def parse_line_audio(line):
    b_buff = []

    split = line.split("\t")

    regex_string = "[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]" #No zeros

    #Logcat time format 13:17:07.703
    #Logcat header information
    meta_info = split[0].strip().split(" ")

    for i in meta_info:
        if re.match(regex_string, i) != None:
            ts = i

    #Name of app that call was made from
    host = meta_info[-1]


    for j in range(1,len(split)):
        i = split[j]
        if "Frames" in i:
            frames = int(i.split(":")[1].strip())
        elif "Buffer Bytes" in i:
            buffer = i.split(":")[1].strip()
            byts = buffer.split(" ")
            for b in byts:
                if b == '':
                    continue
                else:
                    b_buff.append(int(b,16))
            b_buff = bytes(b_buff)
            c_buff = str(b_buff)
            buffer = c_buff
            split[j] = "AUDIO BYTES: "+ c_buff
    entry = (host,ts,frames,b_buff)
    ret = " ".join(split)
    
    return ret,entry


def db_thread(entry):
    sql = ''' INSERT INTO Data(host,name,time,bytes,pid,tid,iArg,fArg,isret)
    VALUES(?,?,?,?,?,?,?,?,?) '''
    db.executemany(sql, entry)
    db.commit()
    
def db_thread_audio(entry):

    sql = ''' INSERT INTO Audio(host,time,frames,bytes)
    VALUES(?,?,?,?) '''
    db.executemany(sql, entry)
    db.commit()
      

def line_queue(q,q2):
    while True:
        line = sys.stdin.buffer.readline()
        if b"JACK LOG:" in line:
            q.put(line,block=False)
        elif b"JACK AUDIO LOG:" in line:
            q2.put(line,block=False)
        else:
            q.put(line,block=False)

def similarity_score_thread(q,signaler,tid):
    cache = []
    while not q.empty():
        cache.append(q.get())

    for j in range(len(cache)):
        word = cache[j]
        print(word)
        if "facebook.katan:" not in word and "aoapp.musicall:" not in word:
            continue

        d1 = word.split(":")
        comp_str1 = ""
        for ele in d1:
            if len(ele) > 200:
                comp_str1+=str(ele)
        
        if len(comp_str1) < 200:
            continue
        comp_str1 = comp_str1.replace("\\x","")

        for k in range(j,len(cache)):

            word2 = cache[k]
            if "facebook.katan:" in word2 or "aoapp.musicall:" in word2:
                continue
            
            d2 = word2.split(":")
            comp_str2 = ""
            for ele in d2:
                if len(ele) > 200:
                    comp_str2+=str(ele)
            
            if len(comp_str2) < 200:
                continue    
            
            if word == word2:
                continue
            comp_str2= comp_str2.replace("\\x", "")
            (identity,score,align1,symbol,align2) = water(comp_str1,comp_str2)
            # print(f"call1 = {comp_str1}\t call2 = {comp_str2} \t matching symbs = {symbol}")
            if score > 100:
                with open("comps.txt","a+") as f:
                    f.write(f"HIGH SIMILARITY WITH {word} and {word2}\tScore:{score}\tsymb{symbol}\n")
                # print(f"HIGH SIMILARITY WITH {word} and {word2}\tScore:{score}\tIdent:{identity}\talign1:{align1}\talign2:{align2}\tsymb{symbol}",flush=True,file=sys.stderr)
                
    signaler.send(tid)
    
def finish_threads(threads,insert_array,is_audio,local_cache):
    BULK_INSERT = 1000
    i=0
    running = True


    while running:
        #reseting when search variable is too big.
        if i >= len(threads):
            running = False
            continue
        else:
            #Grabs thread
            t = threads[i]
            #If it is done, get the return value
            if t!= 0:

                if is_audio:
                    l,entry = t.get()
                    
                    if use_db:
                        insert_array.append(entry)

                        if len(insert_array) > BULK_INSERT:
                            Process(target=db_thread_audio,args=(insert_array,)).start()
                            insert_array = []

                else:
                    l,entries = t.get()
                    
                    if use_db:
                        #Make easy to read database entries
                        for entry in entries:
                            insert_array.append(entry)

                        if len(insert_array) > BULK_INSERT:
                            Process(target=db_thread,args=(insert_array,)).start()
                            insert_array = []

                #display the return value
                if display_output and not is_audio:
                    out = str(l).replace("\\x00","")
                    # out = l

                    if preform_comparisons:
                        if "LONG IS" in out:
                            out = entries[0][0] + str(l).replace("\\x00","")
                        
                        if len(key_words) == 1:
                            local_cache.put(out)

                        for word in key_words:
                            if word in out:
                                local_cache.put(out)
                                break
                        
                    print(out,flush=True)
                    


                            
                
                
                #Delete the reference to the thread
                threads[i] = 0
                
            i+=1
    
    
    return insert_array

def main(m,queue,q2,cache):
    
    ALLOWED_THREADS = 30

    pool = Pool(ALLOWED_THREADS)
    pool2 = Pool(ALLOWED_THREADS)

    threads = [0 for i in range(ALLOWED_THREADS)]
    threads2 = [0 for i in range(ALLOWED_THREADS)]
    threads3 = [0 for i in range(ALLOWED_THREADS)]
    threads3 = [0 for i in range(ALLOWED_THREADS)]
    
    insert_array = []
    audio_insert_array = []
    
    c = 0
    c2 = 0
    c3 = 0
    c3 = 0

    while True:

        
        line = queue.get()

        
        if not q2.empty():
            la = q2.get(timeout=1)
        else:
            la= b''
        
        # print(line)
        if b"JACK LOG:" in line or b"JACK FIELDS LOG:" in line or b"JACK INDIRECT REFERENCE TABLE" in line or b"JNI LOCAL REFERENCE" in line or b"GETTING DIRECT BUFFER ADDY:" in line or b"turing" in line or b"Always Sunny:" in line or b"ArtInterpreterToInterpreterBridge" in line or b"ArtInterpreterToCompiledCodeBridge" in line:
            t = pool.apply_async(parse_line,(line.decode(),))
            threads[c] = t
            c+=1
        else:
            print(line)

        if b"AUDIO LOG:" in la:
            t = pool2.apply_async(parse_line_audio,(la.decode(),))
            threads2[c2] = t
            c2+=1
        


        if c >= ALLOWED_THREADS:
            insert_array = finish_threads(threads,insert_array,False,cache)
            if cache.qsize() > 100000 and preform_comparisons:
                t = Process(target=similarity_score_thread,args=(cache,worker,c3))
                threads3[c3] = t
                c3+=1
                
            #Reseting global value
            c=0
        
        
        if c2 >=ALLOWED_THREADS:
            audio_insert_array = finish_threads(threads2,audio_insert_array,True,cache,cache)
            c2 = 0
        
        if c3 >= ALLOWED_THREADS:
            done_count = 0
            for t in threads3:
                t.start()
            
            while done_count < ALLOWED_THREADS:
                tid = caller.recv()
                print(tid)
                threads3[tid] = 0
                done_count+=1

            c3 = 0
        if c3 >= ALLOWED_THREADS:
            done_count = 0
            for t in threads3:
                t.start()
            
            while done_count < ALLOWED_THREADS:
                tid = caller.recv()
                print(tid)
                threads3[tid] = 0
                done_count+=1

            c3 = 0

if __name__ == "__main__":
   
    m = Manager()
    queue = Queue()
    audio_queue = Queue()
    q = mp.JoinableQueue()
    q = mp.JoinableQueue()

    main_proc = Process(target=main, args=(m,queue,audio_queue,q))
    main_proc.start()

    line_queue(queue,audio_queue)