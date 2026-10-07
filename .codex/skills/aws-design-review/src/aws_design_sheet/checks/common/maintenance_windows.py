"""Weekly maintenance-window parsing and UTC window arithmetic."""
import re

DAYS={day:i for i,day in enumerate(('mon','tue','wed','thu','fri','sat','sun'))}


def window(raw,weekly=False):
    if not isinstance(raw,str):return None
    clock=r'([01][0-9]|2[0-3]):([0-5][0-9])'
    point=r'(mon|tue|wed|thu|fri|sat|sun):'+clock if weekly else clock
    m=re.fullmatch(point+'-'+point,raw,re.I)
    if not m:return None
    if weekly:
        a,b,c,d,e,f=m.groups();start=DAYS[a.lower()]*1440+int(b)*60+int(c);end=DAYS[d.lower()]*1440+int(e)*60+int(f);period=10080
    else:
        a,b,c,d=m.groups();start=int(a)*60+int(b);end=int(c)*60+int(d);period=1440
    duration=(end-start)%period
    # Equal endpoints could denote zero duration or a full cycle; do not infer.
    return (start,start+duration) if duration else None
