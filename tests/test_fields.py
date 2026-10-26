"""Field and return-name recovery. No disassembler and no target binary."""
import unittest

from rea_bot.native.body import _name_returns, recover_fields


class Fields(unittest.TestCase):
    def test_two_offsets_become_fields(self):
        text = "n = FIELD[node+0];\nm = FIELD[node+4];\nreturn n;"
        out = recover_fields(text)
        self.assertIn("node->field_0", out)
        self.assertIn("node->field_4", out)
        self.assertNotIn("FIELD[", out)

    def test_adjacent_bytes_stay_mem(self):
        out = recover_fields("a = FIELD[node+0];\nb = FIELD[node+1];")
        self.assertNotIn("->", out)
        self.assertNotIn("FIELD[", out)

    def test_one_offset_stays_mem(self):
        out = recover_fields("n = FIELD[node+8];")
        self.assertIn("mem", out)
        self.assertNotIn("FIELD[", out)
        self.assertNotIn("->", out)

    def test_unnamed_base_stays_mem(self):
        out = recover_fields("n = FIELD[arg0+0];\nm = FIELD[arg0+8];")
        self.assertNotIn("->", out)
        self.assertNotIn("arg0", out)
        self.assertNotIn("FIELD[", out)

    def test_readdir_uses_dirent_names(self):
        text = "entry = readdir(dir);\nkind = FIELD[entry+18];\nname = FIELD[entry+19];\nreturn kind;"
        out = recover_fields(text)
        self.assertIn("entry->d_type", out)
        self.assertIn("entry->d_name", out)
        self.assertNotIn("FIELD[", out)

    def test_one_dirent_offset_stays_mem(self):
        text = "entry = readdir(dir);\nkind = FIELD[entry+18];"
        out = recover_fields(text)
        self.assertIn("mem", out)
        self.assertNotIn("d_type", out)

    def test_stat_buffer_on_x86_64_only(self):
        text = "stat(path, buf);\nmode = FIELD[buf+24];\nsize = FIELD[buf+48];"
        out = recover_fields(text, arch="x86-64")
        self.assertIn("buf->st_mode", out)
        self.assertIn("buf->st_size", out)
        other = recover_fields(text, arch="arm64")
        self.assertIn("buf->field_18", other)
        self.assertIn("buf->field_30", other)
        self.assertNotIn("st_mode", other)

    def test_fstatat_buffer_is_the_third_argument(self):
        text = "fstatat(dirfd, path, buf, 0);\na = FIELD[buf+0];\nb = FIELD[buf+8];"
        out = recover_fields(text, arch="x86-64")
        self.assertIn("buf->st_dev", out)
        self.assertIn("buf->st_ino", out)

    def test_placeholder_cannot_leak(self):
        out = recover_fields("n = FIELD[not closed")
        self.assertNotIn("FIELD[", out)


class ReturnNames(unittest.TestCase):
    def test_readdir_result_is_entry(self):
        text = _name_returns("call_1 = readdir(arg0);\nkind = FIELD[call_1+18];\nlen = FIELD[call_1+16];")
        self.assertIn("entry = readdir(arg0);", text)
        self.assertIn("FIELD[entry+18]", text)
        self.assertNotIn("call_1", text)
        out = recover_fields(text)
        self.assertIn("entry->d_type", out)
        self.assertIn("entry->d_reclen", out)

    def test_second_readdir_is_numbered(self):
        text = _name_returns("call_1 = readdir(dir);\ncall_2 = readdir(dir);")
        self.assertIn("entry = readdir(dir);", text)
        self.assertIn("entry_2 = readdir(dir);", text)

    def test_unknown_call_keeps_call_n(self):
        text = _name_returns("call_1 = add(arg0, 1);")
        self.assertEqual(text, "call_1 = add(arg0, 1);")

    def test_occupied_stem_is_not_reused(self):
        text = _name_returns("entry = 1;\ncall_1 = readdir(dir);")
        self.assertNotIn("entry = readdir", text)
        self.assertIn("readdir(dir)", text)
        self.assertNotIn("call_1", text)
