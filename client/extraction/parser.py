from detectors.utils import get_available_sid
from server.detection.rule import Rule

class Parser:
    def __init__(self, rule_string):
        self.rule_string = rule_string

    def split_rule(self):
        paren_index = self.rule_string.find("(")

        if not paren_index == -1:
            header = self.rule_string[:paren_index]
            options = self.rule_string[paren_index:]

            return header, options
        else:
            header = self.rule_string
            return header, None
        
    def process_header(self, header_string):
        header_items = header_string.strip().split()

        action = header_items[0]
        protocol = header_items[1]
        src_ip = header_items[2]
        src_port = header_items[3]
        dst_ip = header_items[5]
        dst_port = header_items[6]

        return action, protocol, src_ip, src_port, dst_ip, dst_port

    def process_options(self, options_string):
        if not options_string:
            return None
        
        clean_options = options_string.replace("(", "").replace(")", "")

        option_list = [
            option.strip()
            for option in clean_options.split(";")
            if option.strip()
        ]

        for index, option in enumerate(option_list):
            option_list[index] = option.split(":")
            option_list[index][0] = option_list[index][0].strip()
            option_list[index][1] = option_list[index][1].strip()

        option_dict = {}

        for option in option_list:
            option_dict[option[0]] = option[1]

        return option_dict

    def rule_parameters(self):
        split_string = self.split_rule()
        header = self.process_header(split_string[0])
        options = self.process_options(split_string[1])

        has_sid = True if options and "sid" in options.keys() else False

        if not has_sid or not options:
            sid = get_available_sid()
        else:
            sid = options["sid"]

        return sid, header, options
    
    def parse(self):
        sid, (action, protocol, src_ip, src_port, dst_ip, dst_port), options = self.rule_parameters()
        return Rule(sid, action, protocol, src_ip, src_port, dst_ip, dst_port, options)
