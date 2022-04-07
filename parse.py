#!/usr/bin/env python

from constants import *
import re
import glob
import os
import pprint
import logging
import collections
import yaml

pp = pprint.PrettyPrinter(indent=2)
logging.basicConfig(level=logging.INFO, format='%(levelname)s:: %(message)s')

def process_enc_line(line, ext):
    '''
    This function processes each line of the encoding files (rv*). As part of
    the processing, the function ensures that the encoding is legal through the
    following checks::

        - there is no over specification (same bits assigned different values)
        - there is no under specification (some bits not assigned values)
        - bit ranges are in the format hi..lo=val where hi > lo
        - value assigned is representable in the bit range
        - also checks that the mapping of arguments of an instruction exists in
          arg_lut.
    
    If the above checks pass, then the function returns a tuple of the name and
    a dictionary containing basic information of the instruction which includes:
        - variables: list of arguments used by the instruction whose mapping
          exists in the arg_lut dictionary
        - encoding: this contains the 32-bit encoding of the instruction where
          '-' is used to represent position of arguments and 1/0 is used to
          reprsent the static encoding of the bits
        - extension: this field contains the rv* filename from which this
          instruction was included
        - match: hex value representing the bits that need to match to detect
          this instruction
        - mask: hex value representin the bits that need to be masked to extract
          the value required for matching.
    '''
    single_dict = {}

    # fill all bits with don't care. we use '-' to represent don't care
    # TODO: hardcoded for 32-bits. 
    encoding = ['-'] * 32

    # get the name of instruction by splitting based on the first space
    [name, remaining] = line.split(' ', 1)

    # replace dots with underscores as dot doesn't work with C/Sverilog, etc
    name = name.replace('.', '_')

    # remove leading whitespaces
    remaining = remaining.lstrip()

    # check each field for it's length and overlapping bits
    # ex: 1..0=5 will result in an error --> x<y
    # ex: 5..0=0 2..1=2 --> overlapping bits
    temp_instr = ['-'] * 32
    entries = [
        x[0] for x in re.findall(
            r'((\d)+\.\.(\d)+\=((0b\d+)|(0x\d+)|(\d)+))*',
            remaining) if x[0] != ''
    ]
    for temp_entry in entries:
        entry = temp_entry.split('=')[0]
        f1, f2 = entry.split('..')
        for ind in range(int(f1), int(f2)):

            # overlapping bits
            if temp_instr[ind] == 'X':
                logging.error(
                    f'{line.split(" ")[0]:<10} has {ind} bit overlapping in it\'s opcodes'
                )
                raise SystemExit(1)
            temp_instr[ind] = 'X'

            # check x < y
            if int(f1) < int(f2):
                logging.error(
                    f'{line.split(" ")[0]:<10} has position {f1} less than position {f2} in it\'s encoding'
                )
                raise SystemExit(1)

        # illegal value assigned as per bit width
        entry_value = temp_entry.split('=')[1]
        temp_base = 16 if 'x' in entry_value else 2 if 'b' in entry_value else 10
        if len(str(int(entry_value,
                       temp_base))[2:]) > (int(f1) - int(f2)):
            logging.error(
                f'{line.split(" ")[0]:<10} has an illegal value {entry_value} assigned as per the bit width {f1 - f2}'
            )
            raise SystemExit(1)

    # extract bit pattern assignments of the form hi..lo=val. fixed_ranges is a
    # regex expression present in constants.py. The extracted patterns are
    # captured as a list in args where each entry is a tuple (msb, lsb, value)
    args = fixed_ranges.sub(' ', remaining)

    # parse through the args and assign constants 1/0 to bits which need to be
    # hardcoded for this instruction
    for (msb, lsb, value) in fixed_ranges.findall(remaining):
        value = int(value, 0)
        msb = int(msb, 0)
        lsb = int(lsb, 0)
        value = f"{value:032b}"
        for i in range(0, msb - lsb + 1):
            encoding[31 - (i + lsb)] = value[31 - i]

    # do the same as above but for <lsb>=<val> pattern. single_fixed is a regex
    # expression present in constants.py
    for (lsb, value, drop) in single_fixed.findall(remaining):
        lsb = int(lsb, 0)
        value = int(value, 0)
        encoding[31 - lsb] = str(value)

    # convert the list of encodings into a single string for match and mask
    match = "".join(encoding).replace('-','0')
    mask = "".join(encoding).replace('0','1').replace('-','0')

    # check if all args of the instruction are present in arg_lut present in
    # constants.py
    args = single_fixed.sub(' ', args).split()
    for a in args:
        if a not in arg_lut:
            logging.error(f' Found variable {a} in instruction {name} whose mapping in arg_lut does not exist')
            raise SystemExit(1)

    # update the fields of the instruction as a dict and return back along with
    # the name of the instruction
    single_dict['encoding'] = "".join(encoding)
    single_dict['variable_fields'] = args
    single_dict['extension'] = [ext.split('/')[-1]]
    single_dict['match']=hex(int(match,2))
    single_dict['mask']=hex(int(mask,2))

    return (name, single_dict)


def create_inst_dict(file_filter):
    '''
    This function return a dictionary containing all instructions associated
    with an extension defined by the file_filter input. The file_filter input
    needs to be rv* file name with out the 'rv' prefix i.e. '_i', '32_i', etc.

    Each node of the dictionary will correspond to an instruction which again is
    a dictionary. The dictionary contents of each instruction includes:
        - variables: list of arguments used by the instruction whose mapping
          exists in the arg_lut dictionary
        - encoding: this contains the 32-bit encoding of the instruction where
          '-' is used to represent position of arguments and 1/0 is used to
          reprsent the static encoding of the bits
        - extension: this field contains the rv* filename from which this
          instruction was included
        - match: hex value representing the bits that need to match to detect
          this instruction
        - mask: hex value representin the bits that need to be masked to extract
          the value required for matching.
   
    In order to build this dictionary, the function does 2 passes over the same
    rv<file_filter> file. The first pass is to extract all standard
    instructions. In this pass, all pseudo ops and imported instructions are
    skipped. For each selected line of the file, we call process_enc_line
    function to create the above mentioned dictionary contents of the
    instruction. Checks are performed in this function to ensure that the same
    instruction is not added twice to the overall dictionary.

    In the second pass, this function parses only pseudo_ops. For each pseudo_op
    this function checks if the dependent extension and instruction, both, exit
    before parsing it. The pseudo op is only added to the overall dictionary is
    the dependent instruction is not present in the dictionary, else its
    skipped.


    '''
    opcodes_dir = f'./'
    filtered_inst = {}

    # file_names contains all files to be parsed in the riscv-opcodes directory
    file_names = glob.glob(f'{opcodes_dir}rv{file_filter}')
    file_names += glob.glob(f'{opcodes_dir}unratified/rv{file_filter}')

    # first pass if for standard/original instructions
    logging.debug('Collecting standard instructions first')
    for f in file_names:
        logging.debug(f'Parsing File: {f}')
        with open(f) as fp:
            lines = (line.rstrip()
                     for line in fp)  # All lines including the blank ones
            lines = list(line for line in lines if line)  # Non-blank lines
            lines = list(
                line for line in lines
                if not line.startswith("#"))  # remove comment lines

        # go through each line of the file
        for line in lines:
            # if the an instruction needs to be imported then go to the
            # respective file and pick the line that has the instruction.
            # The variable 'line' will now point to the new line from the
            # imported file

            # ignore all lines starting with $import and $pseudo
            if '$import' in line or '$pseudo' in line:
                continue
            logging.debug(f'     Processing line: {line}')

            # call process_enc_line to get the data about the current
            # instruction
            (name, single_dict) = process_enc_line(line, f)

            # if an instruction has already been added to the filtered 
            # instruction dictionary throw an error saying the given 
            # instruction is already imported and raise SystemExit
            if name in filtered_inst:
                var = filtered_inst[name]["extension"]
                if filtered_inst[name]['encoding'] != single_dict['encoding']:
                    err_msg = f'instruction : {name} from '
                    err_msg += f'{f.split("/")[-1]} is already '
                    err_msg += f'added from {var} but each have different encodings for the same instruction'
                    logging.error(err_msg)
                    raise SystemExit(1)
                filtered_inst[name]['extension'].append(single_dict['extension'])

            # update the final dict with the instruction
            filtered_inst[name] = single_dict
    
    # second pass if for pseudo instructions
    logging.debug('Collecting pseudo instructions now')
    for f in file_names:
        logging.debug(f'Parsing File: {f}')
        with open(f) as fp:
            lines = (line.rstrip()
                     for line in fp)  # All lines including the blank ones
            lines = list(line for line in lines if line)  # Non-blank lines
            lines = list(
                line for line in lines
                if not line.startswith("#"))  # remove comment lines

        # go through each line of the file
        for line in lines:

            # ignore all lines not starting with $pseudo
            if '$pseudo' not in line:
                continue
            logging.debug(f'     Processing line: {line}')

            # use the regex pseudo_regex from constants.py to find the dependent
            # extension, dependent instruction, the pseudo_op in question and
            # its encoding
            (ext, orig_inst, pseudo_inst, line) = pseudo_regex.findall(line)[0]

            # check if the file of the dependent extension exist. Throw error if
            # it doesn't
            if not os.path.exists(ext):
                ext1 = f'unratified/{ext}'
                if not os.path.exists(ext1):
                    logging.error(f'Pseudo op {pseudo_inst} in {f} depends on {ext} which is not available')
                    raise SystemExit(1)
                else:
                    ext = ext1

            # check if the dependent instruction exist in the dependent
            # extension. Else throw error.
            found = False
            for oline in open(ext):
                if not re.findall(f'^\s*{orig_inst}',oline):
                    continue
                else:
                    found = True
                    break
            if not found:
                logging.error(f'Orig instruction {orig_inst} not found in {ext}. Required by pseudo_op {pseudo_inst} present in {f}')
                raise SystemExit(1)


            # add the pseudo_op to the dictionary only if the original
            # instruction is not already in the dictionary.    
            if orig_inst.replace('.','_') not in filtered_inst:
                (name, single_dict) = process_enc_line(pseudo_inst + ' ' + line, f)

                # update the final dict with the instruction
                if name not in filtered_inst:
                    filtered_inst[name] = single_dict
            else:
                logging.debug(f'Skipping pseudo_op {pseudo_inst} since original instruction {orig_inst} already selected in list')
    return filtered_inst

def make_priv_latex_table():
    latex_file = open('priv-instr-table.tex','w')
    type_list = ['R-type','I-type']
    system_instr = ['_h','_s','_system','_svinval', '64_h']
    dataset_list = [ (system_instr, 'Trap-Return Instructions',['sret','mret']) ]
    dataset_list.append((system_instr, 'Interrupt-Management Instructions',['wfi']))
    dataset_list.append((system_instr, 'Supervisor Memory-Management Instructions',['sfence_vma']))
    dataset_list.append((system_instr, 'Hypervisor Memory-Management Instructions',['hfence_vvma', 'hfence_gvma']))
    dataset_list.append((system_instr, 'Hypervisor Virtual-Machine Load and Store Instructions', 
        ['hlv_b','hlv_bu', 'hlv_h','hlv_hu', 'hlv_w', 'hlvx_hu', 'hlvx_wu', 'hsv_b', 'hsv_h','hsv_w']))
    dataset_list.append((system_instr, 'Hypervisor Virtual-Machine Load and Store Instructions, RV64 only', ['hlv_wu','hlv_d','hsv_d']))
    dataset_list.append((system_instr, 'Svinval Memory-Management Instructions', ['sinval_vma', 'sfence_w_inval','sfence_inval_ir', 'hinval_vvma','hinval_gvma']))
    caption = '\\caption{RISC-V Privileged Instructions}'
    make_ext_latex_table(type_list, dataset_list, latex_file, 32, caption)

    latex_file.close()

def make_latex_table():
    '''
    This function is mean to create the instr-table.tex that is meant to be used
    by the riscv-isa-manual. This function basically creates a single latext
    file of multiple tables with each table limited to a single page. Only the
    last table is assigned a latex-caption.

    For each table we assign a type-list which capture the different instruction
    types (R, I, B, etc) that will be required for the table. Then we select the
    list of extensions ('_i, '32_i', etc) whose instructions are required to
    populate the table. For each extension or collection of extension we can
    assign Title, such that in the end they appear as subheadings within
    the table (note these are inlined headings and not captions of the table). 

    All of the above information is collected/created and sent to
    make_ext_latex_table function to dump out the latex contents into a file.

    The last table only has to be given a caption - as per the policy of the
    riscv-isa-manual.
    '''
    # open the file and use it as a pointer for all further dumps
    latex_file = open('instr-table.tex','w')

    # create the rv32i table first. Here we set the caption to empty. We use the
    # files rv_i and rv32_i to capture instructions relevant for rv32i
    # configuration. The dataset is a list of 3-element tuples : 
    # (list_of_extensions, title, list_of_instructions). If list_of_instructions 
    # is empty then it indicates that all instructions of the all the extensions
    # in list_of_extensions need to be dumped. If not empty, then only the
    # instructions listed in list_of_instructions will be dumped into latex.
    caption = ''
    type_list = ['R-type','I-type','S-type','B-type','U-type','J-type']
    dataset_list = [(['_i','32_i'], 'RV32I Base Instruction Set', [])]
    dataset_list.append((['_pseudo'], '', ['fence_tso', 'pause']))
    make_ext_latex_table(type_list, dataset_list, latex_file, 32, caption)

    type_list = ['R-type','I-type','S-type']
    dataset_list = [(['64_i'], 'RV64I Base Instruction Set (in addition to RV32I)', [])]
    dataset_list.append((['_zifencei'], 'RV32/RV64 Zifencei Standard Extension', []))
    dataset_list.append((['_zicsr'], 'RV32/RV64 Zicsr Standard Extension', []))
    dataset_list.append((['_m','32_m'], 'RV32M Standard Extension', []))
    dataset_list.append((['64_m'],'RV64M Standard Extension (in addition to RV32M)', []))
    make_ext_latex_table(type_list, dataset_list, latex_file, 32, caption)

    type_list = ['R-type']
    dataset_list = [(['_a'],'RV32A Standard Extension', [])]
    dataset_list.append((['64_a'],'RV64A Standard Extension (in addition to RV32A)', []))
    make_ext_latex_table(type_list, dataset_list, latex_file, 32, caption)
    
    type_list = ['R-type','R4-type','I-type','S-type']
    dataset_list = [(['_f'],'RV32F Standard Extension', [])]
    dataset_list.append((['64_f'],'RV64F Standard Extension (in addition to RV32F)', []))
    make_ext_latex_table(type_list, dataset_list, latex_file, 32, caption)

    type_list = ['R-type','R4-type','I-type','S-type']
    dataset_list = [(['_d'],'RV32D Standard Extension', [])]
    dataset_list.append((['64_d'],'RV64D Standard Extension (in addition to RV32D)', []))
    make_ext_latex_table(type_list, dataset_list, latex_file, 32, caption)
    
    type_list = ['R-type','R4-type','I-type','S-type']
    dataset_list = [(['_q'],'RV32Q Standard Extension', [])]
    dataset_list.append((['64_q'],'RV64Q Standard Extension (in addition to RV32Q)', []))
    make_ext_latex_table(type_list, dataset_list, latex_file, 32, caption)

    caption = '\\caption{Instruction listing for RISC-V}'
    type_list = ['R-type','R4-type','I-type','S-type']
    dataset_list = [(['_zfh', '_d_zfh','_q_zfh'],'RV32Zfh Standard Extension', [])]
    dataset_list.append((['64_zfh'],'RV64Zfh Standard Extension (in addition to RV32Zfh)', []))
    make_ext_latex_table(type_list, dataset_list, latex_file, 32, caption)
   
    ## The following is demo to show that Compressed instructions can also be
    # dumped in the same manner as above
    #type_list = ['']
    #dataset_list = [(['_c', '32_c', '32_c_f','_c_d'],'RV32C Standard Extension', [])]
    #dataset_list.append((['64_c'],'RV64C Standard Extension (in addition to RV32C)', []))
    #make_ext_latex_table(type_list, dataset_list, latex_file, 16, caption)

    latex_file.close()

def make_ext_latex_table(type_list, dataset, latex_file, ilen, caption):
    '''
    For a given collection of extensions this function dumps out a complete
    latex table which includes the encodings of the instructions.

    The ilen input indicates the length of the instruction for which the table
    is created.

    The caption input is used to create the latex-table caption.

    The type_list input is a list of instruction types (R, I, B, etc) that are
    treated as header for each table. Each table will have its own requirements
    and type_list must include all the instruction-types that the table needs.
    Note, all elements of this list must be present in the latex_inst_type
    dictionary defined in constants.py

    The latex_file is a file pointer to which the latex-table will dumped into

    The dataset is a list of 3-element tuples containing:
        (list_of_extensions, title, list_of_instructions)
    The list_of_extensions must contain all the set of extensions whose
    instructions must be populated under a given title. If list_of_instructions
    is not empty, then only those instructions mentioned in list_of_instructions
    present in the extension will be dumped into the latex-table, other
    instructions will be ignored.

    Once the above inputs are received then function first creates table entries
    for the instruction types. To simplify things, we maintain a dictionary
    called latex_inst_type in constants.py which is created in the same way the
    instruction dictionary is created. This allows us to re-use the same logic
    to create the instruction types table as well

    Once the header is created, we then parse through every entry in the
    dataset. For each list dataset entry we use the create_inst_dict function to
    create an exhaustive list of instructions associated with the respective
    collection of the extension of that dataset. Then we apply the instruction 
    filter, if any, indicated by the list_of_instructions of that dataset.
    Thereon, for each instruction we create a latex table entry.

    Latex table specification for ilen sized instructions:
        Each table is created with ilen+1 columns - ilen columns for each bit of the
        instruction and one column to hold the name of the instruction.

        For each argument of an instruction we use the arg_lut from constants.py
        to identify its position in the encoding, and thus create a multicolumn
        entry with the name of the argument as the data. For hardcoded bits, we
        do the same where we capture a string of continuous 1s and 0s, identify
        the position and assign the same string as the data of the
        multicolumn entry in the table.

    '''
    column_size = "".join(['p{0.002in}']*(ilen+1))

    type_entries = '''
    \\multicolumn{3}{l}{31} & 
    \\multicolumn{2}{r}{27} & 
    \\multicolumn{1}{c}{26} &
    \\multicolumn{1}{r}{25} &
    \\multicolumn{3}{l}{24} &
    \\multicolumn{2}{r}{20} &
    \\multicolumn{3}{l}{19} &
    \\multicolumn{2}{r}{15} &
    \\multicolumn{2}{l}{14} &
    \\multicolumn{1}{r}{12} &
    \\multicolumn{4}{l}{11} &
    \\multicolumn{1}{r}{7} &
    \\multicolumn{6}{l}{6} & 
    \\multicolumn{1}{r}{0} \\\\
    \\cline{2-33}\n& \n\n
''' if ilen == 32 else '''
    \\multicolumn{1}{c}{15} & 
    \\multicolumn{1}{c}{14} & 
    \\multicolumn{1}{c}{13} &
    \\multicolumn{1}{c}{12} &
    \\multicolumn{1}{c}{11} &
    \\multicolumn{1}{c}{10} &
    \\multicolumn{1}{c}{9} &
    \\multicolumn{1}{c}{8} &
    \\multicolumn{1}{c}{7} &
    \\multicolumn{1}{c}{6} &
    \\multicolumn{1}{c}{5} &
    \\multicolumn{1}{c}{4} &
    \\multicolumn{1}{c}{3} & 
    \\multicolumn{1}{c}{2} & 
    \\multicolumn{1}{c}{1} & 
    \\multicolumn{1}{c}{0} \\\\
    \\cline{2-17}\n& \n\n
'''

    # depending on the type_list input we create a subset dictionary of
    # latex_inst_type dictionary present in constants.py
    type_dict = {key: value for key, value in latex_inst_type.items() if key in type_list}

    # iterate ovr each instruction type and create a table entry
    for t in type_dict:
        fields = []

        # first capture all "arguments" of the type (funct3, funct7, rd, etc)
        # and capture their positions using arg_lut.
        for f in type_dict[t]['variable_fields']:
            (msb, lsb) = arg_lut[f]
            name = f if f not in latex_mapping else latex_mapping[f]
            fields.append((msb, lsb, name))

        # iterate through the 32 bits, starting from the msb, and assign
        # argument names to the relevant portions of the instructions. This
        # information is stored as a 3-element tuple containing the msb, lsb
        # position of the arugment and the name of the argument.
        msb = ilen - 1
        y = ''
        for r in range(0,ilen):
            if y != '':
                fields.append((msb,ilen-1-r+1,y))
                y = ''
            msb = ilen-1-r-1
            if r == 31:
                if y != '':
                    fields.append((msb, 0, y))
                y = ''

        # sort the arguments in decreasing order of msb position
        fields.sort(key=lambda y: y[0], reverse=True)

        # for each argument/string of 1s or 0s, create a multicolumn latex table
        # entry
        entry = ''
        for r in range(len(fields)):
            (msb, lsb, name) = fields[r]
            if r == len(fields)-1:
                entry += f'\\multicolumn{{ {msb -lsb +1} }}{{|c|}}{{ {name} }} & {t} \\\\ \n'
            elif r == 0:
                entry += f'\\multicolumn{{ {msb- lsb + 1} }}{{|c|}}{{ {name} }} &\n'
            else:
                entry += f'\\multicolumn{{ {msb -lsb + 1} }}{{c|}}{{ {name} }} &\n'
        entry += f'\\cline{{2-{ilen+1}}}\n&\n\n'
        type_entries += entry

    # for each entry in the dataset create a table
    content = ''
    for (ext_list, title, filter_list) in dataset:
        filtered_inst = {}

        # for all extensions list in ext_list, create a dictionary of
        # instructions associated with those extensions.
        for e in ext_list:
            filtered_inst.update(create_inst_dict(e))

        # if filter_list is not empty then use that as the official set of
        # instructions that need to be dumped into the latex table
        inst_list = list(filtered_inst.keys()) if not filter_list else filter_list

        # for each instruction create an latex table entry just like how we did
        # above with the instruction-type table.
        instr_entries = ''
        for inst in inst_list:
            if inst not in filtered_inst:
                logging.error(f'in make_ext_latex_table: Instruction: {inst} not found in filtered_inst dict')
                raise SystemExit(1)
            fields = []

            # only if the argument is available in arg_lut we consume it, else
            # throw error.
            for f in filtered_inst[inst]['variable_fields']:
                if f not in arg_lut:
                    logging.error(f'Found variable {f} in instruction {inst} whose mapping is not available')
                    raise SystemExit(1)
                (msb,lsb) = arg_lut[f]
                name = f.replace('_','.') if f not in latex_mapping else latex_mapping[f]
                fields.append((msb, lsb, name))

            msb = ilen -1
            y = ''
            if ilen == 16:
                encoding = filtered_inst[inst]['encoding'][16:]
            else:
                encoding = filtered_inst[inst]['encoding']
            for r in range(0,ilen):
                x = encoding [r]
                if ((msb, ilen-1-r+1)) in latex_fixed_fields:
                    fields.append((msb,ilen-1-r+1,y))
                    msb = ilen-1-r
                    y = ''
                if x == '-':
                    if y != '':
                        fields.append((msb,ilen-1-r+1,y))
                        y = ''
                    msb = ilen-1-r-1
                else:
                    y += str(x)
                if r == ilen-1:
                    if y != '':
                        fields.append((msb, 0, y))
                    y = ''

            fields.sort(key=lambda y: y[0], reverse=True)
            entry = ''
            for r in range(len(fields)):
                (msb, lsb, name) = fields[r]
                if r == len(fields)-1:
                    entry += f'\\multicolumn{{ {msb -lsb +1} }}{{|c|}}{{ {name} }} & {inst.upper().replace("_",".")} \\\\ \n'
                elif r == 0:
                    entry += f'\\multicolumn{{ {msb- lsb + 1} }}{{|c|}}{{ {name} }} &\n'
                else:
                    entry += f'\\multicolumn{{ {msb -lsb + 1} }}{{c|}}{{ {name} }} &\n'
            entry += f'\\cline{{2-{ilen+1}}}\n&\n\n'
            instr_entries += entry

        # once an entry of the dataset is completed we create the whole table
        # with the title of that dataset as sub-heading (sort-of)
        if title != '':
            content += f'''

\\multicolumn{{{ilen}}}{{c}}{{}} & \\\\
\\multicolumn{{{ilen}}}{{c}}{{\\bf {title} }} & \\\\
\\cline{{2-{ilen+1}}}

            &
{instr_entries}
'''
        else:
            content += f'''
{instr_entries}
'''

        
    header = f'''
\\newpage

\\begin{{table}}[p]
\\begin{{small}}
\\begin{{center}}
    \\begin{{tabular}} {{{column_size}l}}
    {" ".join(['&']*ilen)} \\\\

            &
{type_entries}
'''
    endtable=f'''

\\end{{tabular}}
\\end{{center}}
\\end{{small}}
{caption}
\\end{{table}}
'''
    # dump the contents and return
    latex_file.write(header+content+endtable)
    
   
def make_chisel(filtered_inst):

    chisel_names=''
    cause_names_str=''
    csr_names_str = ''
    for i in filtered_inst:
        chisel_names += f'  def {i.upper().replace(".","_"):<18s} = BitPat("b{filtered_inst[i]["encoding"].replace("-","?")}")\n'
    for num, name in causes:
        cause_names_str += f'  val {name.lower().replace(" ","_")} = {hex(num)}\n'
    cause_names_str += '''  val all = {
    val res = collection.mutable.ArrayBuffer[Int]()
'''
    for num, name in causes:
        cause_names_str += f'    res += {name.lower().replace(" ","_")}\n'
    cause_names_str += '''    res.toArray
  }'''

    for num, name in csrs+csrs32:
        csr_names_str += f'  val {name} = {hex(num)}\n'
    csr_names_str += '''  val all = {
    val res = collection.mutable.ArrayBuffer[Int]()
'''
    for num, name in csrs:
        csr_names_str += f'''    res += {name}\n'''
    csr_names_str += '''    res.toArray
  }
  val all32 = {
    val res = collection.mutable.ArrayBuffer(all:_*)
'''
    for num, name in csrs32:
        csr_names_str += f'''    res += {name}\n'''
    csr_names_str += '''    res.toArray
  }'''
    
    chisel_file = open('inst.chisel','w')
    chisel_file.write(f'''
/* Automatically generated by parse_opcodes */
object Instructions {{
{chisel_names}
}}
object Causes {{
{cause_names_str}
}}
object CSRs {{
{csr_names_str}
}}
''')
    chisel_file.close()

def make_rust(filtered_inst):
    mask_match_str= ''
    for i in filtered_inst:
        mask_match_str += f'const MATCH_{i.upper().replace(".","_")}: u32 = {(filtered_inst[i]["match"])};\n'
        mask_match_str += f'const MASK_{i.upper().replace(".","_")}: u32 = {(filtered_inst[i]["mask"])};\n'
    for num, name in csrs+csrs32:
        mask_match_str += f'const CSR_{name.upper()}: u16 = {hex(num)};\n'
    for num, name in causes:
        mask_match_str += f'const CAUSE_{name.upper().replace(" ","_")}: u8 = {hex(num)};\n'
    rust_file = open('inst.rs','w')
    rust_file.write(f'''
/* Automatically generated by parse_opcodes */
{mask_match_str}
''')
    rust_file.close()

def make_sverilog(filtered_inst):
    names_str = ''
    for i in filtered_inst:
        names_str += f"  localparam [31:0] {i.upper().replace('.','_'):<18s} = 32'b{filtered_inst[i]['encoding'].replace('-','?')};\n"
    names_str += '  /* CSR Addresses */\n'
    for num, name in csrs+csrs32:
        names_str += f"  localparam logic [11:0] CSR_{name.upper()} = 12'h{hex(num)[2:]};\n"

    sverilog_file = open('inst.sverilog','w')
    sverilog_file.write(f'''
/* Automatically generated by parse_opcodes */
package riscv_instr;
{names_str}
endpackage
''')
    sverilog_file.close()
def make_c(filtered_inst):
    mask_match_str = ''
    declare_insn_str = ''
    for i in filtered_inst:
        mask_match_str += f'#define MATCH_{i.upper().replace(".","_")} {filtered_inst[i]["match"]}\n'
        mask_match_str += f'#define MASK_{i.upper().replace(".","_")} {filtered_inst[i]["mask"]}\n'
        declare_insn_str += f'DECLARE_INSN({i.replace(".","_")}, MATCH_{i.upper().replace(".","_")}, MASK_{i.upper().replace(".","_")})\n'

    csr_names_str = ''
    declare_csr_str = ''
    for num, name in csrs+csrs32:
        csr_names_str += f'#define CSR_{name.upper()} {hex(num)}\n'
        declare_csr_str += f'DECLARE_CSR({name}, CSR_{name.upper()})\n'

    causes_str= ''
    declare_cause_str = ''
    for num, name in causes:
        causes_str += f"#define CAUSE_{name.upper().replace(' ', '_')} {hex(num)}\n"
        declare_cause_str += f"DECLARE_CAUSE(\"{name}\", CAUSE_{name.upper().replace(' ','_')})\n"

    with open('encoding.h', 'r') as file:
        enc_header = file.read()

    enc_file = open('encoding.out.h','w')    
    enc_file.write(f'''
/*
* This file is auto-generated by running xxx in 
* https://github.com/riscv/riscv-opcodes (xxxxxx)
*/
{enc_header}
/* Automatically generated by parse_opcodes. */
#ifndef RISCV_ENCODING_H
#define RISCV_ENCODING_H
{mask_match_str}
{csr_names_str}
{causes_str}
#endif
#ifdef DECLARE_INSN
{declare_insn_str}
#endif
#ifdef DECLARE_CSR
{declare_csr_str}
#endif
#ifdef DECLARE_CAUSE
{declare_cause_str}
#endif
''')
    enc_file.close()

if __name__ == "__main__":
    filtered_inst = create_inst_dict('*')
    with open('filtered_inst.yaml', 'w') as outfile:
        yaml.dump(filtered_inst, outfile, default_flow_style=False)
    filtered_inst = collections.OrderedDict(sorted(filtered_inst.items()))
    make_c(filtered_inst)
    logging.info('encoding.out.h generated successfully')
    make_chisel(filtered_inst)
    logging.info('inst.chisel generated successfully')
    make_sverilog(filtered_inst)
    logging.info('inst.sverilog generated successfully')
    make_rust(filtered_inst)
    logging.info('inst.rs generated successfully')
    make_latex_table()
    logging.info('instr-table.tex generated successfully')
    make_priv_latex_table()
    logging.info('priv-instr-table.tex generated Successfully')
