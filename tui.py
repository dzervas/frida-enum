import urwid

def handle_input(key):
    if key in ("q", "Q"):
        raise urwid.ExitMainLoop()
    elif key in ("k", "up"):
        listboxes[columns.focus_position].focus_position = (listboxes[columns.focus_position].focus_position - 1) % len(listboxes[columns.focus_position].body)
    elif key in ("j", "down"):
        listboxes[columns.focus_position].focus_position = (listboxes[columns.focus_position].focus_position + 1) % len(listboxes[columns.focus_position].body)
    else:
        footer_text.set_text(f"{key} - Part: {frame.get_focus()} Col: {columns.focus_position} List: {listboxes[columns.focus_position].focus_position} / {len(listboxes[columns.focus_position].body)}")

data = []
raw_data = ["a", "b", "c"]*100

for d in raw_data:
    text = urwid.Text(markup=d)
    attrmap = urwid.AttrMap(text, "default", "focus")

    data.append(attrmap)

listboxes = []

for t in ["Modules", "Imports", "Exports", "Symbols"]:
    # title = urwid.Text(markup=("default", t), align="center")

    walker = urwid.SimpleFocusListWalker(data)
    listbox = urwid.ListBox(walker)
    listboxes.append(listbox)

columns = urwid.Columns(listboxes)

header_text = urwid.Text(markup="Frida-Enum TUI", align="center")
footer_text = urwid.Text(markup="Footer", align="center")
header = urwid.AttrMap(header_text, "header")
footer = urwid.AttrMap(footer_text, "header")

frame = urwid.Frame(columns, header, footer, "body")

pallete = [
    ("default", "white", "black"),
    ("focus", "black", "dark red"),
    ("header", "black", "light gray"),
]

loop = urwid.MainLoop(frame, pallete, unhandled_input=handle_input)
loop.run()
