#!/usr/local/bin/python3

import sys
import base64


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

        # types: [OP, REGISTER, LONG_NUM, NUM, STRING, ARRAY]
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
            instruction += [('REGISTER', dst_reg), ('NUM', num)]

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
            instruction += [('LONG_NUM', func_offset), ('REGISTER', return_reg), ('ARRAY', args_array)]

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
            instruction += [('REGISTER', condition_reg), ('LONG_NUM', jump_location)]

        elif op == "JUMP":
            """
            JUMP jump_location
            """
            jump_location = load_long_num()
            instruction += [('LONG_NUM', jump_location)]

        elif op == "JUMP_COND_NEG":
            """
            JUMP_COND_NEG condition_reg jump_location

            load condition (bool expr) from condition_reg
            if not condition, jump to jump_location 
            """

            condition_reg = self.get_byte()
            jump_location = load_long_num()
            instruction += [('REGISTER', condition_reg), ('LONG_NUM', jump_location)]

        elif op == "BCFUNC_CALLBACK":
            """
            BCFUNC_CALLBACK dst_reg func_location arguments
            """

            dst_reg = self.get_byte()
            func_location = load_long_num()
            arguments = load_array()
            instruction += [('REGISTER', dst_reg), ('LONG_NUM', func_location), ('ARRAY', arguments)]

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

        instruction = {
            'instruction': instruction,
            'bytecode_start': bytecode_start,
            'bytecode_end': self.bytecode_pointer,
            'corresponding_bytecode': self.bytecode[bytecode_start:self.bytecode_pointer]
        }

        self.disassembled.append(instruction)

    # perform linear disassembly of loaded bytecode
    def linear_disassemble(self, bytecode):
        while self.bytecode_pointer < len(self.bytecode):
            self.process_instruction()


    def display_assembly(self):
        for instruction in self.disassembled:
            display = ""
            for data_type, data in instruction['instruction']:
                if data_type in ['OP', 'NUM', 'LONG_NUM', 'FLOAT']:
                    display += str(data)
                elif data_type == 'REGISTER':
                    display += 'r' + str(data)
                elif data_type == 'STRING':
                    display += '"' + str(data) + '"'
                elif data_type == 'ARRAY':
                    display += '[' + ', '.join(['r'+str(x) for x in data]) + ']'
                else:
                    display += "(data type display not implemented)"
                display += " "

            print(str(instruction['bytecode_start']) + ': ' + display)

if __name__ == '__main__':
    bytecode_b64 = open(sys.argv[1]).read()
    bytecode = base64.b64decode(bytecode_b64)

    disassembler = Disassembler(bytecode)
    disassembler.linear_disassemble(bytecode)
    disassembler.display_assembly()
