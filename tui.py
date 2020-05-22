from __future__ import unicode_literals, print_function

import urwid
from frida_tools.application import ConsoleApplication

import frida_wrap

URWID_LOOP = None


class WaterfallTUI():
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

        header_text = urwid.Text("frida-enum TUI", align="center")
        footer_text = urwid.Text("Footer", align="center")
        self.u_header = urwid.AttrMap(header_text, "header")
        self.u_footer = urwid.AttrMap(footer_text, "footer")

        self.u_frame = urwid.Frame(self.u_columns, self.u_header, self.u_footer, "body")

        loop = urwid.MainLoop(self.u_frame, self.pallete, unhandled_input=self.handle_input)
        loop.run()

    @property
    def selected_col(self):
        return self.u_columns.focus_position

    @selected_col.setter
    def set_selected_col(self, val):
        self.u_columns.focus_position = val

    @property
    def selected_row(self):
        return self.u_lists[self.selected_col].focus_position

    @selected_row.setter
    def set_selected_row(self, val):
        self.u_lists[self.selected_col].focus_position = val

    def set_column_data(self, i, data):
        self.u_lists[i].body.contents = data

    def handle_input(self, key):
        if key in ("q", "Q"):
            raise urwid.ExitMainLoop()
        elif key in ("r", "R") and hasattr(self.items[self.selected_col], "_reload"):
            self.items[self.selected_col] = self.items[self.selected_col]._reload(self)
        elif key == "enter" and hasattr(self.items[self.selected_col], "_select"):
            self.items[self.selected_col]._select(self, self.items[self.selected_col][self.selected_row])
        elif key in ("k", "up"):
            self.u_lists[self.u_columns.focus_position].focus_position = (self.u_lists[self.u_columns.focus_position].focus_position - 1) % len(self.u_lists[self.u_columns.focus_position].body)
        elif key in ("j", "down"):
            self.u_lists[self.u_columns.focus_position].focus_position = (self.u_lists[self.u_columns.focus_position].focus_position + 1) % len(self.u_lists[self.u_columns.focus_position].body)
        else:
            self.u_footer.original_widget.set_text(f"{key} - Part: {self.u_frame.get_focus()} Col: {self.u_columns.focus_position} List: {self.u_lists[self.u_columns.focus_position].focus_position} / {len(self.u_lists[self.u_columns.focus_position].body)}")


class ItemList(list):
    _select = None
    _reload = None



def main():
    wrap = frida_wrap.FridaWrap()
    wrap.load_file_script("frida_enum.js")

    columns = [
        {
            "Modules": wrap.script.exports.modules,
            # "Threads": wrap.script.exports.threads,
            # "Kernel Modules": wrap.script.exports.kernel_modules,
            "Java Classes": wrap.script.exports.java_loaded_classes,
            "Java Loaders": wrap.script.exports.java_class_loaders,
            "ObjC Classes": wrap.script.exports.objc_classes,
            "ObjC Instances": wrap.script.exports.objc_instances,
            "ObjC Protocols": wrap.script.exports.objc_protocols,
        },
    ]

    def select_module(context, item):
        names = ItemList([x["name"] for x in wrap.script.exports.module_exports(item["name"])])
        context.set_column_data(context.selected_col + 1, names)

    modules = ItemList(wrap.script.exports.modules())
    modules._select = select_module
    # modules._reload = wrap.script.exports.modules

    cols = [("Modules", print), ("Exports", print)]
    items = [modules, ItemList()]

    tui = WaterfallTUI(cols, items)
    tui.run()

if __name__ == "__main__":
    main()
