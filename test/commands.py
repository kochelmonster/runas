from runas import has_root


class SudoCommands:
    def is_root(self):
        return has_root()
