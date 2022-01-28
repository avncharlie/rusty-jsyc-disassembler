#!/usr/local/bin/python3

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
        self.bytecode = bytecode
        self.bytecode_pointer = 0
        self.disassembled = []
        self.jump_table = {}
        self.no_labels = 0

    # keep generating label names for jumps
    def generate_label_name(self):
        overflow = 1
        modulus_label_no = self.no_labels
        self.no_labels += 1 # increment for next time
        while modulus_label_no > 25:
            overflow += 1
            modulus_label_no -= 26

        return string.ascii_lowercase[modulus_label_no] * overflow

    # get current byte and increment bytecode pointer
    def get_byte(self):
        byte = self.bytecode[self.bytecode_pointer]
        self.bytecode_pointer += 1
        return byte

    # read instruction at current bytecode pointer
    # increment bytecode_pointer to next instruction 
    def process_instruction(self):

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
        # JUMP = LONG_NUM used for jump locatiosn
        instruction = [('OP', op)]

        # loader 
        if op == "LOAD_STRING":
            """
            LOAD_STRING dst_reg stringlen string
            """
            dst_reg = self.get_byte()
            size, string = load_string()
            instruction += [('REGISTER', dst_reg), ('NUM', size), ('STRING', string)]

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

            array elements are registers to generate array from
            array will be constructed using them current register values
            array will then be loaded into dst_reg
            """

            dst_reg = self.get_byte()
            arr = load_array()
            instruction += [('REGISTER', dst_reg), ('ARRAY', arr)]

        # misc
        elif op == "PROPACCESS":
            """
            PROPACCESS dst_reg obj_reg prop_reg

            loads object stored in obj_reg
            loads property stored in prop_reg

            stores object[property] in dst_reg
            """

            dst_reg = self.get_byte()
            obj_reg = self.get_byte()
            prop_reg = self.get_byte()

            instruction += [('REGISTER', dst_reg), ('REGISTER', obj_reg), ('REGISTER', prop_reg)] 

        elif op == "FUNC_CALL":
            """
            FUNC_CALL dst_reg func_reg func_context_reg arguments
            """

            dst_reg = self.get_byte()
            func_reg = self.get_byte()
            func_context_reg = self.get_byte()
            arguments = load_array()

            instruction += [('REGISTER', dst_reg), ('REGISTER', func_reg), ('REGISTER', func_context_reg), ('ARRAY', arguments)]

        elif op == "EVAL":
            """
            EVAL dst_reg str_reg

            load string from str_reg, evaluate and store result in dst_reg
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
            instruction += [('JUMP', func_offset), ('REGISTER', return_reg), ('ARRAY', args_array)]

        elif op == "RETURN_BCFUNC": 
            """
            RETURN_BCFUNC return_reg excepted_regs

            return_reg = register which holds return value
            excepted_regs = registers that shouldn't be restored after function
            exits
            """

            return_reg = self.get_byte()
            excepted_regs = load_array()
            instruction += [('REGISTER', return_reg), ('ARRAY', excepted_regs)]

        elif op == "COPY":
            """
            COPY dst_reg src_reg

            copy value in src_reg into dst_reg
            """

            dst_reg = self.get_byte()
            src_reg = self.get_byte()
            instruction += [('REGISTER', dst_reg), ('REGISTER', src_reg)]

        elif op == "EXIT": 
            """
            EXIT 
            op code
            """
            pass

        elif op == "COND_JUMP":
            """
            COND_JUMP condition_reg jump_location

            load condition (bool expr) from condition_reg
            if condition, jump to jump_location 
            """

            condition_reg = self.get_byte()
            jump_location = load_long_num()
            instruction += [('REGISTER', condition_reg), ('JUMP', jump_location)]

        elif op == "JUMP":
            """
            JUMP jump_location
            """
            jump_location = load_long_num()
            instruction += [('JUMP', jump_location)]

        elif op == "JUMP_COND_NEG":
            """
            JUMP_COND_NEG condition_reg jump_location

            load condition (bool expr) from condition_reg
            if not condition, jump to jump_location 
            """

            condition_reg = self.get_byte()
            jump_location = load_long_num()
            instruction += [('REGISTER', condition_reg), ('JUMP', jump_location)]

        elif op == "BCFUNC_CALLBACK":
            """
            BCFUNC_CALLBACK dst_reg func_location arguments

            Callbacks in rusty are:
                an actual JS function in register
                that copies the arguments given to it (the actual JS function) to argument registers
                then run the VM at a bytecode function that is the actual function (and pushes to stack and all)
            The BCFUNC_CALLBACK instruction creates this JS function and stores it in a register
            """

            dst_reg = self.get_byte()
            func_location = load_long_num()
            arguments = load_array()
            instruction += [('REGISTER', dst_reg), ('JUMP', func_location), ('ARRAY', arguments)]

        elif op == "PROPSET":
            """
            PROPSET obj_reg prop_reg val_reg

            load object from obj_reg
            load property from prop_reg
            load value from val_reg
            set object[property] to value
            """

            obj_reg = self.get_byte()
            prop_reg = self.get_byte()
            val_reg = self.get_byte()
            instruction += [('REGISTER', obj_reg), ('REGISTER', prop_reg), ('REGISTER', val_reg)]

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
            instruction += [('REGISTER', catch_except_reg), ('LONG_NUM', catch_location), ('LONG_NUM', finally_location)]

        elif op == "THROW":
            """
            THROW throw_reg

            throw error stored in throw_reg
            """
            throw_reg = self.get_byte()
            instruction += [('REGISTER', throw_reg)]

        elif op == "NOP":
            """
            NOP

            no operation
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
            instruction += [('REGISTER', dst_reg), ('REGISTER', left_reg), ('REGISTER', right_reg)]

        elif op == "COMP_NOT_EQUAL":
            """
            COMP_NOT_EQUAL dst_reg left_reg right_reg
            """
            dst_reg = self.get_byte()
            left_reg = self.get_byte()
            right_reg = self.get_byte()
            instruction += [('REGISTER', dst_reg), ('REGISTER', left_reg), ('REGISTER', right_reg)]

        elif op == "COMP_STRICT_EQUAL":
            """
            COMP_STRICT_EQUAL dst_reg left_reg right_reg
            """
            dst_reg = self.get_byte()
            left_reg = self.get_byte()
            right_reg = self.get_byte()
            instruction += [('REGISTER', dst_reg), ('REGISTER', left_reg), ('REGISTER', right_reg)]

        elif op == "COMP_STRICT_NOT_EQUAL":
            """
            COMP_STRICT_NOT_EQUAL dst_reg left_reg right_reg
            """
            dst_reg = self.get_byte()
            left_reg = self.get_byte()
            right_reg = self.get_byte()
            instruction += [('REGISTER', dst_reg), ('REGISTER', left_reg), ('REGISTER', right_reg)]

        elif op == "COMP_LESS_THAN":
            """
            COMP_LESS_THAN dst_reg left_reg right_reg

            dst = left < right
            """
            dst_reg = self.get_byte()
            left_reg = self.get_byte()
            right_reg = self.get_byte()
            instruction += [('REGISTER', dst_reg), ('REGISTER', left_reg), ('REGISTER', right_reg)]

        elif op == "COMP_GREATHER_THAN": 
            """
            COMP_GREATHER_THAN dst_reg left_reg right_reg

            dst = left > right
            """
            dst_reg = self.get_byte()
            left_reg = self.get_byte()
            right_reg = self.get_byte()
            instruction += [('REGISTER', dst_reg), ('REGISTER', left_reg), ('REGISTER', right_reg)]

        elif op == "COMP_LESS_THAN_EQUAL": 
            """
            COMP_LESS_THAN dst_reg left_reg right_reg

            dst = left <= right
            """
            dst_reg = self.get_byte()
            left_reg = self.get_byte()
            right_reg = self.get_byte()
            instruction += [('REGISTER', dst_reg), ('REGISTER', left_reg), ('REGISTER', right_reg)]

        elif op == "COMP_GREATHER_THAN_EQUAL": 
            """
            COMP_GREATHER_THAN dst_reg left_reg right_reg

            dst = left >= right
            """
            dst_reg = self.get_byte()
            left_reg = self.get_byte()
            right_reg = self.get_byte()
            instruction += [('REGISTER', dst_reg), ('REGISTER', left_reg), ('REGISTER', right_reg)]

        # math
        elif op == "ADD":
            """
            ADD dst_reg src0_reg src1_reg
            """
            dst_reg = self.get_byte()
            src0_reg = self.get_byte()
            src1_reg = self.get_byte()
            instruction += [('REGISTER', dst_reg), ('REGISTER', src0_reg), ('REGISTER', src1_reg)]

        elif op == "MUL":
            """
            MUL dst_reg src0_reg src1_reg
            """
            dst_reg = self.get_byte()
            src0_reg = self.get_byte()
            src1_reg = self.get_byte()
            instruction += [('REGISTER', dst_reg), ('REGISTER', src0_reg), ('REGISTER', src1_reg)]

        elif op == "MINUS":
            """
            MINUS dst_reg src0_reg src1_reg
            """
            dst_reg = self.get_byte()
            src0_reg = self.get_byte()
            src1_reg = self.get_byte()
            instruction += [('REGISTER', dst_reg), ('REGISTER', src0_reg), ('REGISTER', src1_reg)]

        elif op == "DIV":
            """
            DIV dst_reg src0_reg src1_reg
            """
            dst_reg = self.get_byte()
            src0_reg = self.get_byte()
            src1_reg = self.get_byte()
            instruction += [('REGISTER', dst_reg), ('REGISTER', src0_reg), ('REGISTER', src1_reg)]


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
                    # if label does not exist, create label and applye it
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

    # perform linear disassembly of loaded bytecode
    def linear_disassemble(self, bytecode):
        while self.bytecode_pointer < len(self.bytecode):
            self.process_instruction()

    # recombulate all instruction bytecode
    # update bytecode
    def re_assemble(self):
        assembled = b''
        for instruction in self.disassembled:
            assembled += instruction['bytecode']

        self.bytecode = assembled
        return assembled

    # add instructions at certain index 
    # will update and apply jump table
    # will also fix bytecode_start and bytecode_end
    # will also re_assemble
    def insert_instructions(self, instructions, instruction_insert_index):
        """
        instructions:
        given instructions must be of similar form of the parsed instructions
        they must AT LEAST have the 'bytecode' attribute
        they must come in a list

        index:
        the index refers to the instruction number where the new instructions
        will be inserted. the first new instruction's index will be this given
        index. (note: this is not a bytecode index)
        """

        bytecode_insert_index = \
                self.disassembled[instruction_insert_index]['bytecode_start']

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

        # fix bytecode_start and bytecode_end of bumped instructions
        for bumped_i in range(instruction_insert_index, len(self.disassembled)):
            self.disassembled[bumped_i]['bytecode_start'] += insert_length
            self.disassembled[bumped_i]['bytecode_end'] += insert_length

        # fix bytecode_start and bytecode_end of new instructions
        new_start_index = bytecode_insert_index
        for new_instr in instructions:
            new_instr['bytecode_start'] = new_start_index
            new_start_index += len(new_instr['bytecode'])
            new_instr['bytecode_end'] = new_start_index

        # insert into disassembled
        self.disassembled = self.disassembled[:instruction_insert_index] \
                + instructions + self.disassembled[instruction_insert_index:]

        # reassemble
        self.re_assemble()


    # go through labelled instructions and make the jumps equal what is in the jump table
    def apply_jump_table(self):
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
                    new_jump_bytes = self.jump_table[data].to_bytes(4, byteorder='big')

                    #print() # DEBUG
                    #print(list(instruction['bytecode'])) # DEBUG

                    instruction['bytecode'] = instruction['bytecode'][:bytecode_pointer] \
                            + new_jump_bytes + instruction['bytecode'][bytecode_pointer+4:]

                    #print(list(instruction['bytecode'])) # DEBUG

                    # DEBUG:
                    #a,b,c,d = instruction['bytecode'][bytecode_pointer], \
                    #    instruction['bytecode'][bytecode_pointer + 1], \
                    #    instruction['bytecode'][bytecode_pointer + 2], \
                    #    instruction['bytecode'][bytecode_pointer + 3]
                    #current = a << 24 | b << 16 | c << 8 | d
                    #print(self.jump_table[data], current)

    def display_assembly(self, show_bytecode_index=False, use_labels=True):
        for instruction in self.disassembled:
            display = ""
            if show_bytecode_index:
                display = str(instruction['bytecode_start']) + ': '

            for data_type, data in instruction['instruction']:
                if data_type in ['OP', 'NUM', 'LONG_NUM', 'FLOAT']:
                    display += str(data)
                elif data_type == 'JUMP':
                    #display +=  '(' +  data + ', ' + str(self.jump_table[data]) + ')' # debug
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
        return base64.b64encode(self.bytecode)

def NOP():
    return {
        'instruction': [('OP', 'NOP')],
        'bytecode': (24).to_bytes(1, byteorder='big')
    }

def NOPify(disassembler):
    instr_amt = len(disassembler.disassembled)
    
    curr_insert = 0
    while curr_insert < instr_amt*2:
        disassembler.insert_instructions([NOP()], curr_insert)
        curr_insert += 2

if __name__ == '__main__':
    bytecode_b64 = open(sys.argv[1]).read()
    bytecode = base64.b64decode(bytecode_b64)

    disassembler = Disassembler(bytecode)
    disassembler.linear_disassemble(bytecode)
    #disassembler.display_assembly(show_bytecode_index=True, use_labels=False) # not fancy assembly display
    #print('-'*30)
    disassembler.display_assembly(show_bytecode_index=False, use_labels=True) # fancy assembly display


    #print(disassembler.export_bytecode()) # prints b64 encrypted bytecode to use in VM
    #print(disassembler.jump_table) # prints jump table

    # use this to nopify and display loaded bytecode:
    #NOPify(disassembler); print()
    #disassembler.display_assembly(show_bytecode_index=True, use_labels=False)
    #print(disassembler.export_bytecode())
    #print(disassembler.jump_table)
