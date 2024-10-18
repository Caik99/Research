# !pip insatll pefile

import pefile


#Name of the PE file
lott = [
'Virus.Win32.Lamer.ks-5f2d62f2768019af615b717ecb0a64924642fcd5a53d2db51731525b43ef2113',
'Virus.Win32.Lamer.ks-608d10f9f2432b9abe8e4ee736310df5f9a4bf800ffeb6f65b51a37ef9b315a3',
'Virus.Win32.Lamer.ks-60976c3d92e1deafd81517f8425a7a29aa0aaa563fd422c6e2bcd728072470a2',
'Virus.Win32.Lamer.ks-6113c1c3af868d857c99f0d532423f2dee9962a2aeb07f374bfb54919348892b',
'Virus.Win32.Lamer.ks-611cb4a09cbc864430e519edbafeff985c06f3a81a259dbe4b4b0baec1f993a5',
'Virus.Win32.Lamer.ks-6140b2908846fde3a19f74d9a7624336e6775ff79b4dcccff4adf50c71504001'
]


#Location of PE files 
path= "/media/kali/USER/Virusshare.malware/virus/"



    



def DOIT( pe,sName):
    # pe = pefile.PE(path+sName)
# ////// extraction start here//////////////
    e_magic = pe.DOS_HEADER.e_magic
    e_cblp = pe.DOS_HEADER.e_cblp
    e_cp = pe.DOS_HEADER.e_cp
    e_crlc = pe.DOS_HEADER.e_crlc
    e_cparhdr = pe.DOS_HEADER.e_cparhdr
    e_minalloc = pe.DOS_HEADER.e_minalloc
    e_maxalloc = pe.DOS_HEADER.e_maxalloc
    e_ss = pe.DOS_HEADER.e_ss
    e_sp = pe.DOS_HEADER.e_sp
    e_csum = pe.DOS_HEADER.e_csum
    e_ip = pe.DOS_HEADER.e_ip
    e_cs = pe.DOS_HEADER.e_cs
    e_lfarlc = pe.DOS_HEADER.e_lfarlc
    e_ovno = pe.DOS_HEADER.e_ovno
    e_oemid = pe.DOS_HEADER.e_oemid
    e_oeminfo = pe.DOS_HEADER.e_oeminfo
    e_lfanew = pe.DOS_HEADER.e_lfanew
    Machine = pe.FILE_HEADER.Machine
    NumberOfSections = pe.FILE_HEADER.NumberOfSections
    TimeDateStamp = pe.FILE_HEADER.TimeDateStamp
    PointerToSymbolTable = pe.FILE_HEADER.PointerToSymbolTable
    NumberOfSymbols = pe.FILE_HEADER.NumberOfSymbols
    SizeOfOptionalHeader = pe.FILE_HEADER.SizeOfOptionalHeader
    Characteristics = pe.FILE_HEADER.Characteristics

    Magic = pe.OPTIONAL_HEADER.Magic
    MajorLinkerVersion = pe.OPTIONAL_HEADER.MajorLinkerVersion
    MinorLinkerVersion = pe.OPTIONAL_HEADER.MinorLinkerVersion
    SizeOfCode = pe.OPTIONAL_HEADER.SizeOfCode
    SizeOfInitializedData = pe.OPTIONAL_HEADER.SizeOfInitializedData
    SizeOfUninitializedData = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    AddressOfEntryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    BaseOfCode = pe.OPTIONAL_HEADER.BaseOfCode
    ImageBase = pe.OPTIONAL_HEADER.ImageBase
    SectionAlignment = pe.OPTIONAL_HEADER.SectionAlignment
    FileAlignment = pe.OPTIONAL_HEADER.FileAlignment
    MajorOperatingSystemVersion = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
    MinorOperatingSystemVersion = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    MajorImageVersion = pe.OPTIONAL_HEADER.MajorImageVersion
    MinorImageVersion = pe.OPTIONAL_HEADER.MinorImageVersion
    MajorSubsystemVersion = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    MinorSubsystemVersion = pe.OPTIONAL_HEADER.MinorSubsystemVersion
    SizeOfHeaders = pe.OPTIONAL_HEADER.SizeOfHeaders
    CheckSum = pe.OPTIONAL_HEADER.CheckSum
    SizeOfImage = pe.OPTIONAL_HEADER.SizeOfImage
    Subsystem = pe.OPTIONAL_HEADER.Subsystem
    DllCharacteristics = pe.OPTIONAL_HEADER.DllCharacteristics
    
    SizeOfStackReserve = pe.OPTIONAL_HEADER.SizeOfStackReserve
    SizeOfStackCommit = pe.OPTIONAL_HEADER.SizeOfStackCommit
    SizeOfHeapReserve = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    SizeOfHeapCommit = pe.OPTIONAL_HEADER.SizeOfHeapCommit
    LoaderFlags = pe.OPTIONAL_HEADER.LoaderFlags
    NumberOfRvaAndSizes = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes



    content=[]
    with open('suspicious_functions.txt') as f:
        content = f.readlines()
    content = [x.strip() for x in content] 
#
    count_suspicious_functions = 0
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for func in entry.imports:
                if func.name.decode('utf-8') in content:
                    count_suspicious_functions+=1
        SuspiciousImportFunctions = count_suspicious_functions
    except AttributeError:
        SuspiciousImportFunctions = 0

    name_packers=[]
    with open('name_packers.txt') as f:
        name_packers = f.readlines()
    name_packers = [x.strip() for x in name_packers] 
#
    number_packers = 0
    try:
        for entry in pe.sections:
            try:
                entry.Name.decode('utf-8')
            except Exception:
                    number_packers+=1
            if entry.Name in name_packers:
                number_packers+=1
          
        SuspiciousNameSection = number_packers
    except AttributeError as e:
        SuspiciousNameSection = 0


    SectionsLength = len(pe.sections)
    section_entropy_dict = {}
    for section in pe.sections:
        section_name = section.Name.decode('utf-8').strip('\x00')
        entropy = section.get_entropy()
        section_entropy_dict[section_name] = entropy
    SectionMinEntropy = min(section_entropy_dict.values())
    SectionMaxEntropy = max(section_entropy_dict.values())

    section_raw_size_dict = {}
    for section in pe.sections:
        section_name = section.Name.decode('utf-8').strip('\x00')
        raw_size = section.SizeOfRawData
        section_raw_size_dict[section_name] = raw_size
    SectionMinRawsize= min(section_raw_size_dict.values())
    SectionMaxRawsize = max(section_raw_size_dict.values())

    section_virt_size_dict = {}
    for section in pe.sections:
        section_name = section.Name.decode('utf-8').strip('\x00')
        virt_size = section.Misc_VirtualSize
        section_virt_size_dict[section_name] = virt_size        
    SectionMinVirtualsize = min(section_virt_size_dict.values())
    SectionMaxVirtualsize = max(section_virt_size_dict.values())
        
    section_physical_addr_dict = {}
    for section in pe.sections:
        section_name = section.Name.decode('utf-8').strip('\x00')
        physical = section.Misc_PhysicalAddress
        section_physical_addr_dict[section_name] = physical          
    SectionMaxPhysical = max(section_physical_addr_dict.values())
    SectionMinPhysical = min(section_physical_addr_dict.values())
        
    section_virt_addr_dict = {}
    for section in pe.sections:
        section_name = section.Name.decode('utf-8').strip('\x00')
        virtual = section.VirtualAddress
        section_virt_addr_dict[section_name] = virtual
    SectionMaxVirtual = max(section_virt_addr_dict.values())
    SectionMinVirtual = min(section_virt_addr_dict.values())
        
    section_pointer_data_dict = {}
    for section in pe.sections:
        section_name = section.Name.decode('utf-8').strip('\x00')
        pointer_data = section.PointerToRawData
        section_pointer_data_dict[section_name] = pointer_data          
    SectionMaxPointerData = max(section_pointer_data_dict.values())
    SectionMinPointerData = min(section_pointer_data_dict.values())

    section_char_dict = {}
    for section in pe.sections:
        section_name = section.Name.decode('utf-8').strip('\x00')
        chars = section.Characteristics
        section_char_dict[section_name] = chars            
    SectionMaxChar = max(section_char_dict.values())
    SectionMainChar = min(section_char_dict.values())
        
    try:
        DirectoryEntryImport = len(pe.DIRECTORY_ENTRY_IMPORT)
        imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
        DirectoryEntryImportSize = (len(imports))
    except AttributeError:
        DirectoryEntryImport = 0
        DirectoryEntryImportSize =0

        
    try: DirectoryEntryExport = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    except AttributeError: DirectoryEntryExport = 0
        
    ImageDirectoryEntryExport = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].VirtualAddress
    ImageDirectoryEntryImport = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress
    ImageDirectoryEntryResource = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']].VirtualAddress
    ImageDirectoryEntryException = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']].VirtualAddress
    ImageDirectoryEntrySecurity = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress

# /////////end here //////////////////////while writing to afile start here///////////

    with open("testdatase.csv", "a") as f:
    # Write all variables to the file with the specified format
    
        f.write(str(sName) + ",")
        f.write(str(e_magic) + ",")
        f.write(str(e_cblp) + ",")
        f.write(str(e_cp) + ",")
        f.write(str(e_crlc) + ",")
        f.write(str(e_cparhdr) + ",")
        f.write(str(e_minalloc) + ",")
        f.write(str(e_maxalloc) + ",")
        f.write(str(e_ss) + ",")
        f.write(str(e_sp) + ",")
        f.write(str(e_csum) + ",")
        f.write(str(e_ip) + ",")
        f.write(str(e_cs) + ",")
        f.write(str(e_lfarlc) + ",")
        f.write(str(e_ovno) + ",")
        f.write(str(e_oemid) + ",")
        f.write(str(e_oeminfo) + ",")
        f.write(str(e_lfanew) + ",")
        f.write(str(Machine) + ",")
        f.write(str(NumberOfSections) + ",")
        f.write(str(TimeDateStamp) + ",")
        f.write(str(PointerToSymbolTable) + ",")
        f.write(str(NumberOfSymbols) + ",")
        f.write(str(SizeOfOptionalHeader) + ",")
        f.write(str(Characteristics) + ",")
        f.write(str(Magic) + ",")
        f.write(str(MajorLinkerVersion) + ",")
        f.write(str(MinorLinkerVersion) + ",")
        f.write(str(SizeOfCode) + ",")
        f.write(str(SizeOfInitializedData) + ",")
        f.write(str(SizeOfUninitializedData) + ",")
        f.write(str(AddressOfEntryPoint) + ",")
        f.write(str(BaseOfCode) + ",")
        f.write(str(ImageBase) + ",")
        f.write(str(SectionAlignment) + ",")
        f.write(str(FileAlignment) + ",")
        f.write(str(MajorOperatingSystemVersion) + ",")
        f.write(str(MinorOperatingSystemVersion) + ",")
        f.write(str(MajorImageVersion) + ",")
        f.write(str(MinorImageVersion) + ",")
        f.write(str(MajorSubsystemVersion) + ",")
        f.write(str(MinorSubsystemVersion) + ",")
        f.write(str(SizeOfHeaders) + ",")
        f.write(str(CheckSum) + ",")
        f.write(str(SizeOfImage) + ",")
        f.write(str(Subsystem) + ",")
        f.write(str(DllCharacteristics) + ",")
        f.write(str(SizeOfStackReserve) + ",")
        f.write(str(SizeOfStackCommit) + ",")
        f.write(str(SizeOfHeapReserve) + ",")
        f.write(str(SizeOfHeapCommit) + ",")
        f.write(str(LoaderFlags) + ",")
        f.write(str(NumberOfRvaAndSizes) + ",")


        f.write(str(SuspiciousImportFunctions) + ",") 
        f.write(str(SuspiciousNameSection) + ",") 
        f.write(str(SectionsLength) + ",")
        f.write(str(SectionMinEntropy ) + ",")
        f.write(str(SectionMaxEntropy ) + ",")

        f.write(str(SectionMinRawsize) + ",")
        f.write(str(SectionMaxRawsize) + ",")
        f.write(str(SectionMinVirtualsize) + ",")
        f.write(str(SectionMaxVirtualsize) + ",")

        f.write(str(SectionMaxPhysical) + ",")
        f.write(str(SectionMinPhysical) + ",")

        f.write(str(SectionMaxVirtual) + ",")
        f.write(str(SectionMinVirtual) + ",")

        f.write(str(SectionMaxPointerData) + ",")
        f.write(str(SectionMinPointerData) + ",")

        f.write(str(SectionMaxChar) + ",")
        f.write(str(SectionMainChar) + ",")


        f.write(str(DirectoryEntryImportSize) + ",")
        f.write(str(DirectoryEntryImport) + ",")
        f.write(str(DirectoryEntryExport) + ",")

        f.write(str(ImageDirectoryEntryExport) + ",")
        f.write(str(ImageDirectoryEntryImport) + ",")
        f.write(str(ImageDirectoryEntryResource) + ",")
        f.write(str(ImageDirectoryEntryException) + ",")
        f.write(str(ImageDirectoryEntrySecurity) + ",")
        

        #'remeber to alwars change this'
        f.write(str("Virus") + "\n") #Trojan=6,Spyware=3,Worm=2,Virus=1,Rootkit=5,Begin=0
        #''

        #'remeber to alwars change this'
        # f.write(str("AgentTesla_RAT") + " ") #
        # f.write(str("\n"))
    #''
    # end here writitng

for i in lott:
    
    sName = i

    # for file_path in file_paths:
    try:
        pe = pefile.PE(path+sName)
        # Process the PE file if it is valid
        # print(f"Processing {file_path}: Valid PE file")
        DOIT(pe , sName)
    except Exception as e:
        # print(f"Error processing {file_path}: {e}")
        # print("Moving on to the next file...")
        continue
    

