import sys
from html.parser import HTMLParser

class HTMLValidator(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack = []
        self.errors = []
        
    def handle_starttag(self, tag, attrs):
        # Ignore self-closing tags in HTML5
        if tag in ['img', 'input', 'br', 'hr', 'meta', 'link']:
            return
        self.stack.append((tag, self.getpos()))
        
    def handle_endtag(self, tag):
        if tag in ['img', 'input', 'br', 'hr', 'meta', 'link']:
            return
        if not self.stack:
            self.errors.append(f"Unexpected end tag </{tag}> at line {self.getpos()[0]}")
            return
            
        expected_tag, pos = self.stack.pop()
        if expected_tag != tag:
            self.errors.append(f"Mismatched tag </{tag}> at line {self.getpos()[0]}, expected </{expected_tag}> opened at line {pos[0]}")
            # Try to recover by popping until match
            recovered = False
            temp_stack = list(self.stack)
            while temp_stack:
                t, p = temp_stack.pop()
                if t == tag:
                    self.stack = temp_stack
                    recovered = True
                    break
            if not recovered:
                # Put back the popped tag
                self.stack.append((expected_tag, pos))

    def check(self, file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        self.feed(content)
        
        while self.stack:
            tag, pos = self.stack.pop()
            self.errors.append(f"Unclosed tag <{tag}> opened at line {pos[0]}")
            
        return self.errors

validator = HTMLValidator()
errors = validator.check(r"e:\ForensicLogX\frontend\templates\index.html")
if errors:
    print(f"Found {len(errors)} HTML structure errors:")
    for err in errors[:20]:
        print(" -", err)
    sys.exit(1)
else:
    print("HTML Structure is 100% Valid!")
    sys.exit(0)
