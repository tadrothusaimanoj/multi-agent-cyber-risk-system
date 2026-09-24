import re

with open('backend/static/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

match = re.search(r'<script type="text/babel">(.*?)</script>', content, re.DOTALL)
if match:
    react_code = match.group(1).strip()
    
    react_code = react_code.replace('const { useState, useEffect, useRef } = React;', '')
    
    imports = '''"use client";

import React, { useState, useEffect, useRef } from 'react';
import Chart from 'chart.js/auto';

'''
    
    react_code = imports + react_code + '\n\nexport default App;\n'
    
    # Also fix any issues where HTML class is used instead of className (if any, although React standardizes on className)
    # Babel standalone allows some things, but Next.js requires strict TS/JS
    
    with open('src/components/OriginalDashboard.tsx', 'w', encoding='utf-8') as out:
        out.write(react_code)
    print('Successfully extracted to src/components/OriginalDashboard.tsx')
else:
    print('Could not find the babel script block')
