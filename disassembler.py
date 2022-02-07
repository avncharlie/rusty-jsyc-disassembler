#!/usr/bin/env python3

"""
Class to disassemble rusty-jsyc bytecode
Can be imported to use Disassembler class, or be run directly with a command
line argument to a b64 encrypted bytecode file to disassemble it.

Author: Alvin Charles
Email: alvinjoycharles@gmail.com
"""

import sys
import base64
import string


OP_INFO = {
    # Loaders
    1: "LOAD_STRING",
    2: "LOAD_NUM",
    3: "LOAD_FLOAT",
    4: "LOAD_LONG_NUM",
    5: "LOAD_ARRAY",

    # Misc
    10: "PROPACCESS",
    11: "FUNC_CALL",
    12: "EVAL",
    13: "CALL_BCFUNC",
    14: "RETURN_BCFUNC",
    15: "COPY",
    16: "EXIT",
    17: "COND_JUMP",
    18: "JUMP",
    19: "JUMP_COND_NEG",
    20: "BCFUNC_CALLBACK",
    21: "PROPSET",
    22: "TRY",
    23: "THROW",
    24: "NOP",

    # Comparisons
    50: "COMP_EQUAL",
    51: "COMP_NOT_EQUAL",
    52: "COMP_STRICT_EQUAL",
    53: "COMP_STRICT_NOT_EQUAL",
    54: "COMP_LESS_THAN",
    55: "COMP_GREATHER_THAN",
    56: "COMP_LESS_THAN_EQUAL",
    57: "COMP_GREATHER_THAN_EQUAL",

    # Math
    100: "ADD",
    101: "MUL",
    102: "MINUS",
    103: "DIV"
}


class Disassembler:
    def __init__(self, bytecode):
        """
        Load bytecode into disassembler.

        bytecode should be a byte string
        """
        self.bytecode = bytecode
        self.bytecode_pointer = 0
        self.disassembled = []
        self.jump_table = {}
        self.no_labels = 0

    def generate_label_name(self):
        """ Generate label names for jump labels """
        overflow = 1
        modulus_label_no = self.no_labels
        self.no_labels += 1 # increment for next time
        while modulus_label_no > 25:
            overflow += 1
            modulus_label_no -= 26

        return string.ascii_lowercase[modulus_label_no] * overflow

    def get_byte(self):
        """ Return current byte and increment bytecode pointer """
        byte = self.bytecode[self.bytecode_pointer]
        self.bytecode_pointer += 1
        return byte

    def process_instruction(self):
        """
        Process instruction at current bytecode pointer and store in
        self.disassembled.

        Will increment self.bytecode_pointer to start of next instruction.
        Will populate jump table (self.jump_table) as instructions with jumps
        are read.
        """

        # load data from bytecode

        def load_string():
            size = (self.get_byte() << 8) or self.get_byte()
            string = ''.join( [chr(self.get_byte()) for _ in range(size)] )
            return (size, string)

        def load_float():
            binary = ""
            for _ in range(8):
                binary += format(self.get_byte(), '08b')

            sign = -1 if binary[0] == '1' else 1
            exponent = int(binary[1:12], 2)
            significandBase = binary[12:]

            significandBin = 0
            if (exponent == 0):
                if not '1' in significandBase:
                    # exponent and significand are 0
                    return 0
                else:
                    exponent = -0x3fe
                    significandBin = '0' + significandBase
            else:
                exponent -= 0x3ff
                significandBin = '1' + significandBase

            significand = 0
            for x in range(len(significandBin)):
                significand += 2**(-x) * int(significandBin[x])
            return sign * significand * (2**exponent)

        def load_long_num():
            num = self.get_byte() << 24 | self.get_byte() << 16 | \
                  self.get_byte() << 8 | self.get_byte()
            return num

        def load_array():
            arr_size = self.get_byte()
            arr = []
            for x in range(arr_size):
                arr.append(self.get_byte())
            return arr

        bytecode_start = self.bytecode_pointer

        op_code = self.get_byte()
        op = OP_INFO[op_code]

        # types: [OP, REGISTER, LONG_NUM, NUM, STRING, ARRAY, JUMP]
        # JUMPs are LONG_NUM used to mark jump locations
        instruction = [('OP', op)]

        # loader instructions

        if op == "LOAD_STRING":
            """
            LOAD_STRING dst_reg stringlen string
            """
            dst_reg = self.get_byte()
            size, string = load_string()
            instruction += [('REGISTER', dst_reg), ('NUM', size), 
                    ('STRING', string)]

        elif op == "LOAD_NUM":
            """
            LOAD_NUM dst_reg val
            """
            dst_reg = self.get_byte()
            number = self.get_byte()
            instruction += [('REGISTER', dst_reg), ('NUM', number)]

        elif op == "LOAD_FLOAT":
            """
            LOAD_FLOAT dst_reg float
            """

            dst_reg = self.get_byte()
            float_num = load_float()
            instruction += [('REGISTER', dst_reg), ('FLOAT', float_num)]

        elif op == "LOAD_LONG_NUM":
            """
            LOAD_LONG_NUM dst_reg number 
            """

            dst_reg = self.get_byte()
            num = load_long_num()
            instruction += [('REGISTER', dst_reg), ('LONG_NUM', num)]

        elif op == "LOAD_ARRAY":
            """
            LOAD_ARRAY dst_reg array

            Array elements are registers to generate array from
            Array will be constructed using them current register values
            Array will then be loaded into dst_reg
            """

            dst_reg = self.get_byte()
            arr = load_array()
            instruction += [('REGISTER', dst_reg), ('ARRAY', arr)]

        # misc
        elif op == "PROPACCESS":
            """
            PROPACCESS dst_reg obj_reg prop_reg

            Loads object stored in obj_reg
            Loads property stored in prop_reg

            Stores object[property] in dst_reg
            """

            dst_reg = self.get_byte()
            obj_reg = self.get_byte()
            prop_reg = self.get_byte()

            instruction += [('REGISTER', dst_reg), ('REGISTER', obj_reg),
                    ('REGISTER', prop_reg)] 

        elif op == "FUNC_CALL":
            """
            FUNC_CALL dst_reg func_reg func_context_reg arguments
            """

            dst_reg = self.get_byte()
            func_reg = self.get_byte()
            func_context_reg = self.get_byte()
            arguments = load_array()

            instruction += [('REGISTER', dst_reg), ('REGISTER', func_reg),
                    ('REGISTER', func_context_reg), ('ARRAY', arguments)]

        elif op == "EVAL":
            """
            EVAL dst_reg str_reg

            Load string from str_reg, evaluate and store result in dst_reg
            """

            dst_reg = self.get_byte()
            str_reg = self.get_byte()
            instruction += [('REGISTER', dst_reg), ('REGISTER', str_reg)]

        elif op == "CALL_BCFUNC":
            """
            CALL_BCFUNC func_offset return_reg args_array
            """

            func_offset = load_long_num()
            return_reg = self.get_byte()
            args_array = load_array()
            instruction += [('JUMP', func_offset), ('REGISTER', return_reg),
                    ('ARRAY', args_array)]

        elif op == "RETURN_BCFUNC": 
            """
            RETURN_BCFUNC return_reg excepted_regs

            Return_reg = register which holds return value
            Excepted_regs = registers that shouldn't be restored after function
            exits
            """

            return_reg = self.get_byte()
            excepted_regs = load_array()
            instruction += [('REGISTER', return_reg), ('ARRAY', excepted_regs)]

        elif op == "COPY":
            """
            COPY dst_reg src_reg

            Copy value in src_reg into dst_reg
            """

            dst_reg = self.get_byte()
            src_reg = self.get_byte()
            instruction += [('REGISTER', dst_reg), ('REGISTER', src_reg)]

        elif op == "EXIT": 
            """
            EXIT 
            
            Exits VM
            """
            pass

        elif op == "COND_JUMP":
            """
            COND_JUMP condition_reg jump_location

            Load condition (bool expr) from condition_reg
            If condition, jump to jump_location 
            """

            condition_reg = self.get_byte()
            jump_location = load_long_num()
            instruction += [('REGISTER', condition_reg),
                    ('JUMP', jump_location)]

        elif op == "JUMP":
            """
            JUMP jump_location
            """
            jump_location = load_long_num()
            instruction += [('JUMP', jump_location)]

        elif op == "JUMP_COND_NEG":
            """
            JUMP_COND_NEG condition_reg jump_location

            Load condition (bool expr) from condition_reg
            If not condition, jump to jump_location 
            """

            condition_reg = self.get_byte()
            jump_location = load_long_num()
            instruction += [('REGISTER', condition_reg),
                    ('JUMP', jump_location)]

        elif op == "BCFUNC_CALLBACK":
            """
            BCFUNC_CALLBACK dst_reg func_location arguments

            Callbacks in rusty are:
              - An actual JS function in a register
              - That copies the arguments given to it (the actual JS function)
                to argument registers
              - Then runs the VM at a bytecode function that is the actual
                function as well as internally pushing things to stack as if it
                was a normal function.
            The BCFUNC_CALLBACK instruction creates this JS function and stores
            it in a register.
            """

            dst_reg = self.get_byte()
            func_location = load_long_num()
            arguments = load_array()
            instruction += [('REGISTER', dst_reg), ('JUMP', func_location),
                    ('ARRAY', arguments)]

        elif op == "PROPSET":
            """
            PROPSET obj_reg prop_reg val_reg

            Load object from obj_reg
            Load property from prop_reg
            Load value from val_reg
            Set object[property] to value
            """

            obj_reg = self.get_byte()
            prop_reg = self.get_byte()
            val_reg = self.get_byte()
            instruction += [('REGISTER', obj_reg), ('REGISTER', prop_reg),
                    ('REGISTER', val_reg)]

        elif op == "TRY":
            """
            TRY catch_except_reg catch_location finally_location

            if error, put error object into catch_except_reg and run code at
            catch_location
            finally, run at finally_location
            """
            catch_except_reg = self.get_byte()
            catch_location = load_long_num()
            finally_location = load_long_num()
            instruction += [('REGISTER', catch_except_reg),
                    ('LONG_NUM', catch_location),
                    ('LONG_NUM', finally_location)]

        elif op == "THROW":
            """
            THROW throw_reg

            Throw error stored in throw_reg
            """
            throw_reg = self.get_byte()
            instruction += [('REGISTER', throw_reg)]

        elif op == "NOP":
            """
            NOP

            No operation
            """
            pass

        # comparisons
        elif op == "COMP_EQUAL": 
            """
            COMP_EQUAL dst_reg left_reg right_reg
            """
            dst_reg = self.get_byte()
            left_reg = self.get_byte()
            right_reg = self.get_byte()
            instruction += [('REGISTER', dst_reg), ('REGISTER', left_reg),
                    ('REGISTER', right_reg)]

        elif op == "COMP_NOT_EQUAL":
            """
            COMP_NOT_EQUAL dst_reg left_reg right_reg
            """
            dst_reg = self.get_byte()
            left_reg = self.get_byte()
            right_reg = self.get_byte()
            instruction += [('REGISTER', dst_reg), ('REGISTER', left_reg),
                    ('REGISTER', right_reg)]

        elif op == "COMP_STRICT_EQUAL":
            """
            COMP_STRICT_EQUAL dst_reg left_reg right_reg
            """
            dst_reg = self.get_byte()
            left_reg = self.get_byte()
            right_reg = self.get_byte()
            instruction += [('REGISTER', dst_reg), ('REGISTER', left_reg),
                    ('REGISTER', right_reg)]

        elif op == "COMP_STRICT_NOT_EQUAL":
            """
            COMP_STRICT_NOT_EQUAL dst_reg left_reg right_reg
            """
            dst_reg = self.get_byte()
            left_reg = self.get_byte()
            right_reg = self.get_byte()
            instruction += [('REGISTER', dst_reg), ('REGISTER', left_reg),
                    ('REGISTER', right_reg)]

        elif op == "COMP_LESS_THAN":
            """
            COMP_LESS_THAN dst_reg left_reg right_reg

            dst = left < right
            """
            dst_reg = self.get_byte()
            left_reg = self.get_byte()
            right_reg = self.get_byte()
            instruction += [('REGISTER', dst_reg), ('REGISTER', left_reg),
                    ('REGISTER', right_reg)]

        elif op == "COMP_GREATHER_THAN": 
            """
            COMP_GREATHER_THAN dst_reg left_reg right_reg

            dst = left > right
            """
            dst_reg = self.get_byte()
            left_reg = self.get_byte()
            right_reg = self.get_byte()
            instruction += [('REGISTER', dst_reg), ('REGISTER', left_reg),
                    ('REGISTER', right_reg)]

        elif op == "COMP_LESS_THAN_EQUAL": 
            """
            COMP_LESS_THAN dst_reg left_reg right_reg

            dst = left <= right
            """
            dst_reg = self.get_byte()
            left_reg = self.get_byte()
            right_reg = self.get_byte()
            instruction += [('REGISTER', dst_reg), ('REGISTER', left_reg),
                    ('REGISTER', right_reg)]

        elif op == "COMP_GREATHER_THAN_EQUAL": 
            """
            COMP_GREATHER_THAN dst_reg left_reg right_reg

            dst = left >= right
            """
            dst_reg = self.get_byte()
            left_reg = self.get_byte()
            right_reg = self.get_byte()
            instruction += [('REGISTER', dst_reg), ('REGISTER', left_reg),
                    ('REGISTER', right_reg)]

        # math
        elif op == "ADD":
            """
            ADD dst_reg src0_reg src1_reg
            """
            dst_reg = self.get_byte()
            src0_reg = self.get_byte()
            src1_reg = self.get_byte()
            instruction += [('REGISTER', dst_reg), ('REGISTER', src0_reg),
                    ('REGISTER', src1_reg)]

        elif op == "MUL":
            """
            MUL dst_reg src0_reg src1_reg
            """
            dst_reg = self.get_byte()
            src0_reg = self.get_byte()
            src1_reg = self.get_byte()
            instruction += [('REGISTER', dst_reg), ('REGISTER', src0_reg),
                    ('REGISTER', src1_reg)]

        elif op == "MINUS":
            """
            MINUS dst_reg src0_reg src1_reg
            """
            dst_reg = self.get_byte()
            src0_reg = self.get_byte()
            src1_reg = self.get_byte()
            instruction += [('REGISTER', dst_reg), ('REGISTER', src0_reg),
                    ('REGISTER', src1_reg)]

        elif op == "DIV":
            """
            DIV dst_reg src0_reg src1_reg
            """
            dst_reg = self.get_byte()
            src0_reg = self.get_byte()
            src1_reg = self.get_byte()
            instruction += [('REGISTER', dst_reg), ('REGISTER', src0_reg),
                    ('REGISTER', src1_reg)]

        # add jumps to jump table
        existing_jump = False
        for index in range(len(instruction)):
            data_type, jump_location = instruction[index]
            if data_type == 'JUMP':
                for label in self.jump_table:
                    if self.jump_table[label] == jump_location:
                        # apply label if it already exists
                        instruction[index] = ('JUMP', label)
                        existing_jump = True 
                        break
                if not existing_jump:
                    # if label does not exist, create label and apply it
                    new_label = self.generate_label_name()
                    self.jump_table[new_label] = jump_location
                    instruction[index] = ('JUMP', new_label)


        instruction = {
            'instruction': instruction,
            'bytecode_start': bytecode_start,
            'bytecode_end': self.bytecode_pointer,
            'bytecode': self.bytecode[bytecode_start:self.bytecode_pointer]
        }

        self.disassembled.append(instruction)

    def linear_disassemble(self):
        """ Perform linear disassembly of loaded bytecode """
        while self.bytecode_pointer < len(self.bytecode):
            self.process_instruction()

    # recombulate all instruction bytecode
    # update bytecode
    def re_assemble(self):
        """
        Read through instructions and combine together bytecode.
        
        Return combined bytecode as well as updating self.bytecode with it.
        """
        assembled = b''
        for instruction in self.disassembled:
            assembled += instruction['bytecode']

        self.bytecode = assembled
        return assembled

    def add_named_label(self, label_name, location):
        """
        Add named label anywhere in bytecode.

        Useful when inserting instructions (to jump to this label)
        """
        self.jump_table[label_name] = location

    def fix_bytecode_indexes(self):
        """
        Will ensure bytecode_start and bytecode_end values are correct
        Used when inserting / modifying instructions 
        """
        start_bump = 0
        for instruction in self.disassembled:
            instruction['bytecode_start'] = start_bump
            start_bump += len(instruction['bytecode'])
            instruction['bytecode_end'] = start_bump

    def insert_instructions(self, instructions, instruction_insert_index,
            insert_after_index=False):
        """
        Add instructions at a certain index.

        Will change and apply jump table. Will change 'bytecode_start' and 
        'bytecode_end' attributes of all affected instructions. Will also 
        reassemble bytecode.

        Arguments
         -- instructions
        Given instructions must be of similar form of the generated instruction
        dictionaries. They must at least have the 'bytecode' attribute.
        They must be in a list.

        -- instruction_insert_index:
        If insert_after_index, the instruction will be inserted after
        instruction_insert_index.
        If not insert_after_index, instruction will be inserted at
        instruction_insert_index (moving instruction currently there forward)
        """

        if not insert_after_index:
            bytecode_insert_index = \
                self.disassembled[instruction_insert_index]['bytecode_start']
        else:
            bytecode_insert_index = \
                self.disassembled[instruction_insert_index]['bytecode_end']

        bytecode_insert = b''
        for new_instr in instructions:
            bytecode_insert += new_instr['bytecode']
        insert_length = len(bytecode_insert)

        # fix jump table
        for label in self.jump_table:
            if self.jump_table[label] >= bytecode_insert_index:
                self.jump_table[label] += insert_length

        # apply new jump table
        self.apply_jump_table()

        # insert into disassembled
        if not insert_after_index:
            self.disassembled = self.disassembled[:instruction_insert_index] \
                + instructions + self.disassembled[instruction_insert_index:]
        else:
            self.disassembled = self.disassembled[:instruction_insert_index+1] \
                + instructions + self.disassembled[instruction_insert_index+1:]


        # fix bytecode indexes
        self.fix_bytecode_indexes()

        # reassemble
        self.re_assemble()


    def apply_jump_table(self):
        """ 
        Traverse jump table and rewrite instructions jumping to labels to
        correspond to jump locations in jump table.
        """ 

        for instruction in self.disassembled:
            bytecode_pointer = 0
            for data_type, data in instruction['instruction']:
                if data_type in ['OP', 'NUM', 'REGISTER']:
                    bytecode_pointer += 1
                elif data_type == 'LONG_NUM':
                    bytecode_pointer += 4
                elif data_type == 'FLOAT':
                    bytecode_pointer += 8
                elif data_type in ['STRING', 'ARRAY']:
                    # strings and arrays are unbounded length and as such will
                    # will always be at the end of instructions
                    continue
                elif data_type == 'JUMP':
                    new_jump_bytes = self.jump_table[data].to_bytes(4,
                            byteorder='big')

                    instruction['bytecode'] = \
                            instruction['bytecode'][:bytecode_pointer] \
                            + new_jump_bytes \
                            + instruction['bytecode'][bytecode_pointer+4:]

                    # DEBUG:
                    #a,b,c,d = instruction['bytecode'][bytecode_pointer], \
                    #    instruction['bytecode'][bytecode_pointer + 1], \
                    #    instruction['bytecode'][bytecode_pointer + 2], \
                    #    instruction['bytecode'][bytecode_pointer + 3]
                    #current = a << 24 | b << 16 | c << 8 | d
                    #print(self.jump_table[data], current)

    def display_assembly(self, show_bytecode_index=False, use_labels=True):
        """ Display disassembled bytecode """
        for instruction in self.disassembled:
            display = ""
            if show_bytecode_index:
                display = str(instruction['bytecode_start']) + ': '

            for data_type, data in instruction['instruction']:
                if data_type in ['OP', 'NUM', 'LONG_NUM', 'FLOAT']:
                    display += str(data)
                elif data_type == 'JUMP':
                    if use_labels:
                        display += data
                    else:
                        display += str(self.jump_table[data])
                elif data_type == 'REGISTER':
                    display += 'r' + str(data)
                elif data_type == 'STRING':
                    display += '"' + str(data) + '"'
                elif data_type == 'ARRAY':
                    display += '[' + ', '.join(['r'+str(x) for x in data]) + ']'
                else:
                    display += "(data type display not implemented)"
                display += " "

            if use_labels:
                for label in self.jump_table:
                    if self.jump_table[label] == instruction['bytecode_start']:
                        display ='\n' + label + ':\n' + display

            print(display)

    def export_bytecode(self):
        """ Export bytecode to use in VM """
        return base64.b64encode(self.bytecode)


def int_to_byte(n):
    """ convert int into byte """
    return n.to_bytes(1, byteorder='big')

def ints_to_bytes(n_list):
    """ convert a list of ints into a bytestring """
    return b''.join([int_to_byte(x) for x in n_list])

def NOPify(disassembler):
    """ insert NOP instructions every two instructions in bytecode """

    def NOP():
        """ return NOP instruction """
        return {
            'instruction': [('OP', 'NOP')],
            'bytecode': int_to_byte(24)
        }

    instr_amt = len(disassembler.disassembled)
    curr_insert = 0
    while curr_insert < instr_amt*2:
        disassembler.insert_instructions([NOP()], curr_insert)
        curr_insert += 2

def bytecode_base64_string_decoder():
    """
    Return bytecode function to deobfuscate strings

    Function assumes 'atob' is loaded in r203
    Function takes string to deobfuscate in r0 and returns deobfuscated string
    in r1
    """
    decoder = [
        {
            # FUNC_CALL r1 r1000 r253 [r0]
            # deobfuscate string in r0 using atob, store in r1
            'instruction': [('OP', 'FUNC_CALL'), ('REGISTER', 1),
                ('REGISTER', 203), ('REGISTER', 253), ('ARRAY', [0])],
            'bytecode': ints_to_bytes([11, 1, 203, 253, 1, 0])
        },
        {
            # RETURN_BCFUNC r1 []
            # return function with value in r1
            'instruction': [('OP', 'RETURN_BCFUNC'), ('REGISTER', 1),
                ('ARRAY', [])],
            'bytecode': ints_to_bytes([14, 1, 0])
        }
    ]

    return decoder

def base64_string_encode(s):
    """
    Return base64 representation of string
    """
    return base64.b64encode(s.encode('ascii')).decode('ascii')

def obfuscate_strings(disassembler, decoder_bytecode, encoder_func):
    """
    Obfuscate strings in bytecode
    Needs 'this.setReg(203, atob);' to be added to init function in vm
    """

    def EXIT():
        """ return EXIT instruction """
        return {
            'instruction': [('OP', 'EXIT')],
            'bytecode': int_to_byte(16)
        }

    def call_decoder(string_reg):
        """
        Generate instruction to call decoder on string loaded in load_register
        """
        return {
            # CALL_BCFUNC decoder r<string_reg> [r0, r<string_reg>]
            # call decoder, return value in string_reg (overwriting obfuscated
            # str with deobfuscated str), pass string as argument into r0
            'instruction': [('OP', 'CALL_BCFUNC'), ('JUMP', 'decoder'),
                ('REGISTER', string_reg), ('ARRAY', [0, string_reg])],
            'bytecode': ints_to_bytes([13, 0, 0, 0, 0, string_reg, 2, 0,
                string_reg])
        }

    # add decoder to end of bytecode
    disassembler.insert_instructions([EXIT()] + decoder_bytecode,
            len(disassembler.disassembled)-1,
            insert_after_index=True)

    # add label to start of decoder
    disassembler.add_named_label('decoder',
            disassembler.disassembled[-2]['bytecode_start'])

    # insert calls to decoder
    # obfuscate strings
    instruction_index = 0
    while instruction_index < len(disassembler.disassembled):
        instruction = disassembler.disassembled[instruction_index]

        if instruction['instruction'][0][1] == 'LOAD_STRING':
            # insert decoder call
            string_reg = instruction['instruction'][1][1]
            decode_call = call_decoder(string_reg)
            disassembler.insert_instructions([decode_call], instruction_index+1)

            # TODO: should be an 'modify instruction' interface that does this
            # stuff

            # replace original string with encoded string
            orig_str = instruction['instruction'][3][1]
            encoded_str = encoder_func(orig_str)
            encoded_str_len = len(encoded_str)
            instruction['instruction'][2] = ('NUM', encoded_str_len)
            instruction['instruction'][3] = ('STRING', encoded_str)

            new_size_bytes = encoded_str_len.to_bytes(2, byteorder='big')
            encoded_str_bytes = encoded_str.encode('ascii')
            instruction['bytecode'] = instruction['bytecode'][:2] \
                + new_size_bytes + encoded_str_bytes

            # instruction length (could have) changed, re-calculate indices
            disassembler.fix_bytecode_indexes()

            # difference to modify jumps from 
            size_diff = encoded_str_len - len(orig_str)
            
            # fix jump table
            for label in disassembler.jump_table:
                if disassembler.jump_table[label] >= \
                        instruction['bytecode_end']:
                    disassembler.jump_table[label] += size_diff 

            # apply new jump table
            disassembler.apply_jump_table()

        instruction_index += 1

    # combine bytecode together again
    disassembler.re_assemble()


if __name__ == '__main__':

    if len(sys.argv) == 1:
        print('''./disassembler.py bytecode_file [action]*
File to disassemble must be provided.
Any amount of actions can be listed afterwards.
If no actions provided, the display_basic action will trigger.

Examples:
  $ ./disassembler.py file display_fancy
  Display disassembly of file
  
  $ ./disassembler.py file NOPify export_bytecode
  Export NOPIfied bytecode of file

  $ ./disassembler.py file NOPify NOPify export_bytecode
  Export doubly NOPIfied bytecode of file
  
  $ ./disassembler.py file display_fancy obf_strings display_fancy
  1. Display disassembly of file
  2. Obfuscate strings in bytecode
  3. Display disassembly of file (modified from string obfuscation)

Parameters
  bytecode_file: file of Rusty-JSYC base64 encoded bytecode

  actions:
    display_basic: Display basic disassembly of bytecode
    display_fancy: Display disassembly of bytecode with labels
    NOPify: Disperse NOPs throughout loaded bytecode
    obf_strings: Obfuscate strings present in loaded bytecode
    export: Export loaded bytecode (base64 encrypted) to paste into vm
    jumps: Display jump table of loaded bytecode''')
        exit()

    # read bytecode file, decode and disassemble bytecode
    bytecode_b64 = open(sys.argv[1]).read()
    bytecode = base64.b64decode(bytecode_b64)
    disassembler = Disassembler(bytecode)
    disassembler.linear_disassemble()

    action_stack = sys.argv[2:]
    if action_stack == []:
        action_stack = ['display_basic']

    for action in action_stack:
        if action == 'display_basic':
            disassembler.display_assembly(show_bytecode_index=True,
                    use_labels=False) 
            print('------')
        elif action == 'display_fancy':
            disassembler.display_assembly(show_bytecode_index=False,
                    use_labels=True) 
            print('------')
        elif action == 'NOPify':
            NOPify(disassembler)
        elif action == 'obf_strings':
            obfuscate_strings(disassembler, bytecode_base64_string_decoder(),
                    base64_string_encode)
        elif action == 'export':
            print(disassembler.export_bytecode())
            print('------')
        elif action == 'jumps':
            print(disassembler.jump_table)
            print('------')
        else:
            print('action: ' + action + ' not recognised')
