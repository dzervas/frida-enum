from __future__ import unicode_literals, print_function

import urwid
from frida_tools.application import ConsoleApplication

import frida_enum
import frida_wrap

URWID_LOOP = None


class JsonTUI():
    pallete = [
        ("default", "white", "black"),
        ("focus", "black", "dark red"),
        ("header", "black", "light gray"),
        ("footer", "black", "light gray"),
    ]

    def __init__(self, columns, items):
        """
            columns: List<Tuple<Name: str, callback: func>> Column names with callback to fetch data
            items: List<List<Tuple<Name: str, callback: func>>> Items inside each column with callback action
        """
        self.columns = columns
        self.items = items

        self.u_frame = None
        self.u_columns = None
        self.u_lists = []
        self.u_items = []

    def run(self):
        # Create Text object for each item in nested list
        for col in self.items:
            col_attr_items = []

            for row in col:
                # row is Tuple<Name: str, callback: func>
                text = urwid.AttrMap(urwid.Text(row["name"]), "default", "focus")
                col_attr_items.append(text)

            self.u_items.append(col_attr_items)

        # Create ListBox object for each column
        for index, col in enumerate(self.columns):
            # title = urwid.Text(markup=("default", t), align="center")

            walker = urwid.SimpleFocusListWalker(self.u_items[index])
            listbox = urwid.ListBox(walker)
            self.u_lists.append(listbox)

        self.u_columns = urwid.Columns(self.u_lists)

        header_text = urwid.Text("Frida_Enum TUI", align="center")
        footer_text = urwid.Text("Footer", align="center")
        self.u_header = urwid.AttrMap(header_text, "header")
        self.u_footer = urwid.AttrMap(footer_text, "footer")

        self.u_frame = urwid.Frame(self.u_columns, self.u_header, self.u_footer, "body")

        loop = urwid.MainLoop(self.u_frame, self.pallete, unhandled_input=self.handle_input)
        loop.run()

    @staticmethod
    def handle_input(key):
        if key in ("q", "Q"):
            raise urwid.ExitMainLoop()
        elif key in ("k", "up"):
            self.u_lists[self.u_columns.focus_position].focus_position = (self.u_lists[self.u_columns.focus_position].focus_position - 1) % len(self.u_lists[self.u_columns.focus_position].body)
        elif key in ("j", "down"):
            self.u_lists[self.u_columns.focus_position].focus_position = (self.u_lists[self.u_columns.focus_position].focus_position + 1) % len(self.u_lists[self.u_columns.focus_position].body)
        else:
            self.u_footer.set_text(f"{key} - Part: {frame.get_focus()} Col: {columns.focus_position} List: {listboxes[columns.focus_position].focus_position} / {len(listboxes[columns.focus_position].body)}")


def main():
    wrap = frida_wrap.FridaWrap()
    wrap.attach()
    script = frida_enum.script_deploy(wrap.session)

    modules = script.exports.modules()
    cols = [("Modules", print)]
    items = [modules]

    tui = JsonTUI(cols, items)
    tui.run()

if __name__ == "__main__":
    main()
