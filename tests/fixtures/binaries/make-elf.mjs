// Generates a tiny, deterministic x86-64 ELF executable for analysis tests.
//
// It is built byte by byte so every byte can be reviewed. It is never run:
// Revscope and Ghidra only read it. It holds two functions, named in a
// symbol table:
//   answer at 0x400080:  mov eax, 42 ; ret        (b8 2a 00 00 00 c3)
//   twice  at 0x400090:  lea eax, [rdi+rdi] ; ret (8d 04 3f c3)
//
// Layout (file offsets):
//   0x000 ELF header          0x040 program header (one PT_LOAD, R+X)
//   0x080 .text               0x098 .symtab (3 entries)
//   0x0e0 .strtab             0x0ee .shstrtab
//   0x110 section headers (null, .text, .symtab, .strtab, .shstrtab)
//
// Usage: node make-elf.mjs <output path>   (or import { makeElf })
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export const BASE = 0x400000n;
export const FUNCTIONS = [
  { name: "answer", offset: 0x80, bytes: [0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3] },
  { name: "twice", offset: 0x90, bytes: [0x8d, 0x04, 0x3f, 0xc3] },
];

const TEXT = { offset: 0x80, size: 0x14 };
const SYMTAB = { offset: 0x98, size: 3 * 24 };
const STRTAB_TEXT = "\0answer\0twice\0";
const STRTAB = { offset: 0xe0, size: STRTAB_TEXT.length };
const SHSTRTAB_TEXT = "\0.text\0.symtab\0.strtab\0.shstrtab\0";
const SHSTRTAB = { offset: 0xee, size: SHSTRTAB_TEXT.length };
const SECTION_HEADERS = 0x110;
const FILE_SIZE = SECTION_HEADERS + 5 * 64;

export const makeElf = () => {
  const file = Buffer.alloc(FILE_SIZE);
  // ELF header
  file.write("\x7fELF", 0, "latin1");
  file[4] = 2; // ELFCLASS64
  file[5] = 1; // little-endian
  file[6] = 1; // EV_CURRENT
  file.writeUInt16LE(2, 16); // ET_EXEC
  file.writeUInt16LE(62, 18); // EM_X86_64
  file.writeUInt32LE(1, 20);
  file.writeBigUInt64LE(BASE + 0x80n, 24); // entry: answer
  file.writeBigUInt64LE(0x40n, 32); // program headers
  file.writeBigUInt64LE(BigInt(SECTION_HEADERS), 40);
  file.writeUInt16LE(64, 52); // header size
  file.writeUInt16LE(56, 54); // program header size
  file.writeUInt16LE(1, 56); // one program header
  file.writeUInt16LE(64, 58); // section header size
  file.writeUInt16LE(5, 60); // five sections
  file.writeUInt16LE(4, 62); // .shstrtab index

  // PT_LOAD mapping the file from offset 0 through the end of .text, read + execute
  file.writeUInt32LE(1, 0x40);
  file.writeUInt32LE(5, 0x44);
  file.writeBigUInt64LE(0n, 0x48);
  file.writeBigUInt64LE(BASE, 0x50);
  file.writeBigUInt64LE(BASE, 0x58);
  file.writeBigUInt64LE(BigInt(TEXT.offset + TEXT.size), 0x60);
  file.writeBigUInt64LE(BigInt(TEXT.offset + TEXT.size), 0x68);
  file.writeBigUInt64LE(0x1000n, 0x70);

  // .text: int3 padding between the functions
  file.fill(0xcc, TEXT.offset, TEXT.offset + TEXT.size);
  for (const { offset, bytes } of FUNCTIONS) Buffer.from(bytes).copy(file, offset);

  // .symtab: null symbol, then global functions (STB_GLOBAL << 4 | STT_FUNC) in .text (index 1)
  let nameOffset = 1;
  FUNCTIONS.forEach(({ name, offset, bytes }, index) => {
    const at = SYMTAB.offset + (index + 1) * 24;
    file.writeUInt32LE(nameOffset, at);
    file[at + 4] = 0x12;
    file.writeUInt16LE(1, at + 6);
    file.writeBigUInt64LE(BASE + BigInt(offset), at + 8);
    file.writeBigUInt64LE(BigInt(bytes.length), at + 16);
    nameOffset += name.length + 1;
  });
  file.write(STRTAB_TEXT, STRTAB.offset, "latin1");
  file.write(SHSTRTAB_TEXT, SHSTRTAB.offset, "latin1");

  const section = (index, { name, type, flags = 0n, addr = 0n, offset, size, link = 0, info = 0, align, entsize = 0n }) => {
    const at = SECTION_HEADERS + index * 64;
    file.writeUInt32LE(name, at);
    file.writeUInt32LE(type, at + 4);
    file.writeBigUInt64LE(flags, at + 8);
    file.writeBigUInt64LE(addr, at + 16);
    file.writeBigUInt64LE(BigInt(offset), at + 24);
    file.writeBigUInt64LE(BigInt(size), at + 32);
    file.writeUInt32LE(link, at + 40);
    file.writeUInt32LE(info, at + 44);
    file.writeBigUInt64LE(align, at + 48);
    file.writeBigUInt64LE(entsize, at + 56);
  };
  const shName = (name) => SHSTRTAB_TEXT.indexOf(`\0${name}\0`) + 1;
  section(1, { name: shName(".text"), type: 1, flags: 0x6n, addr: BASE + BigInt(TEXT.offset), ...TEXT, align: 16n });
  section(2, { name: shName(".symtab"), type: 2, ...SYMTAB, link: 3, info: 1, align: 8n, entsize: 24n });
  section(3, { name: shName(".strtab"), type: 3, ...STRTAB, align: 1n });
  section(4, { name: shName(".shstrtab"), type: 3, ...SHSTRTAB, align: 1n });
  return file;
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const output = process.argv[2];
  if (output === undefined) {
    process.stderr.write("usage: node make-elf.mjs <output path>\n");
    process.exit(2);
  }
  writeFileSync(output, makeElf());
}
