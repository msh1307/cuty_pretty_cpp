import traceback
is_mangled = lambda x : idc.demangle_name(x,1) != None
demangle = lambda x : idc.demangle_name(x,0b1000) 
x = []

def ext(n,fl):
    idx = []
    ret = ''
    a,sk = 0,0
    if fl & 0b11 == 0b11:
        return ret

    for i,j in enumerate(n):
        if sk:
            sk=0
            continue
        if j == '<':
            if i-8 >= 0:
                if 'operator' == n[i-8:i]:
                    if fl&0b01:
                        sk = 1
                    continue
            idx.append(i)
        elif j == '>':
            if i-1 >= 0:
                if n[i-1]=='-':
                    continue
            if i-8 >= 0:
                if 'operator' == n[i-8:i]:
                    if fl&0b10:
                        sk = 1 
                    continue
            v = idx.pop()
            if len(idx)==0:
                ret += n[a:v]
                a = i+1 
    ret= ret + n[a:]
    if ret == n:
        ret = ''
    return ret

def go(f):
    if is_mangled(idc.get_func_name(f.start_ea)):
        fl = 0
        fn = demangle(idc.get_func_name(f.start_ea))
        mn = idc.get_func_name(f.start_ea)
        if 'operator' in fn:
            if 'ls' in mn:
                fl |= 0b01
            if 'rs' in mn:
                fl |= 0b10
            if 'rS' in mn:
                fl |= 0b110
            if 'lS' in mn:
                fl |= 0b101
        n = ext(fn,fl)
        if n == '':
            return 0xffffffff
            
        org = n
        if fl & 0b01:
            if fl & 0b100:
                n = n.replace('operator<<=','LSA')
            else:
                n = n.replace('operator<<','LS')
        if fl & 0b10:
            if fl & 0b100:
                n = n.replace('operator>>=','RSA')
            else:
                n = n.replace('operator>>','RS')
        n = n.replace('operator==','EQ')
        n = n.replace('operator!=','NQ')
        n = n.replace('operator>','GT')
        n = n.replace('operator<','LT')
        n = n.replace('operator>=','GE')
        n = n.replace('operator<=','LE')
        n = n.replace('operator=','AS')
        n = n.replace('operator++','INC')
        n = n.replace('operator--',"DEC")
        n = n.replace('operator+',"ADD")
        n = n.replace('operator-',"SUB")
        n = n.replace('operator*',"MUL")
        n = n.replace('operator/',"/")
        n = n.replace('operator%',"MOD")
        n = n.replace('operator|',"OR")
        n = n.replace('operator&',"AND")
        n = n.replace('operator~','NOT')

        if idaapi.set_name(f.start_ea,n ,idaapi.SN_NOCHECK | idaapi.SN_FORCE):
            assert idaapi.set_func_cmt(f, 'demangled: '+fn+'\n'+'mangled: '+mn+'\n'+'simplified: '+org+'\n', 1) == True
            return 1
    return 0


if __name__ == '__main__':
    c = 0
    for i in range(ida_funcs.get_func_qty()):
        f= ida_funcs.getn_func(i)
        ret = go(f)
        if ret == 1:
            c += 1
        elif ret == 0xffffffff:
            continue
    print(f'{c} renamed')
