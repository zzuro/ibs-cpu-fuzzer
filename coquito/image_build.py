from typing import List, Tuple
import click
from elftools.elf.elffile import ELFFile


def check_overlap(segments: List[Tuple[str, int, int]], new: Tuple[str, int, int]) -> Tuple[bool, str]:
    """Checks whether :new would overlap with at least one segment of :segments

    Params:
        - segments: A list of segments (see below for the formal definition of a segment)
        - new: The new segment to check overlap against

    Returns: a tuple made of two elements:
        - First element: whether a collision was found (True) or not (False)
        - Second element: if the first element is True, the name/path to the file that would collide with :new, else
            a value that should be disregarded.

    Note:
        - A segment is a three-element tuple: path to file/filename, start address (inclusive), end address (exclusive)
        - The current implementation of this function is very suboptimal with a O(n) runtime. However, this shouldn't be an issue
            in practice as we'll most likely never work with more than ten segments.

    Warning:
        - This function does not insert :new in :segments
    """
    new_name, new_start, new_end = new

    for s in segments:
        s_name, s_start, s_end = s
        if s_start <= new_end < s_end or s_start <= new_start < s_end:
            return (True, s_name)

    return (False, '')


@click.command()
@click.option('--bootloader', "-b", type=click.File(mode='rb'), required=True,
              help="Path to the EDKII modified bootloader raw binary")
@click.option('--coquito', "-c", type=click.File(mode='rb'), required=True, multiple=True,
              help="Path to a COQUITO ELF")
@click.argument('outfile', type=click.File(mode='wb'), required=True)
def cli_entrypoint(bootloader: click.File, coquito: List[click.File], outfile: click.File) -> None:

    # Allocate a 4 MiB in-memory pseudo-OVMF file
    ovmf_file_start = 0xffc00000
    ovmf_file_size = 4 << 20
    ovmf = bytearray(ovmf_file_size)

    # Write the bootloader at the end of the pseudo-OVMF file
    bootloader_content = bootloader.read()
    ovmf[len(ovmf) - len(bootloader_content):] = bootloader_content

    # List of the inserted code segments in the OVMF file (for overlap checks)
    inserted_segments: List[Tuple[str, int, int]] = [
        (bootloader.name,
         ovmf_file_start + ovmf_file_size - len(bootloader_content),
         ovmf_file_start + ovmf_file_size)
    ]

    # Keep track of the .text start addresses for COQUITO ELFs (for catalog generation)
    coquito_text_starts: List[int] = []

    for e_fptr in coquito:
        try:
            elf_file = ELFFile(e_fptr)
        except Exception as e:
            click.echo(f"FATAL: Failed to open '{e_fptr.name}' as an ELF file: {e}", err=True)
            raise SystemExit(1)

        text_section = elf_file.get_section_by_name(".text")
        if text_section is None:
            click.echo(f"FATAL: Missing .text section in '{e_fptr.name}'", err=True)
            raise SystemExit(1)

        # See https://stackoverflow.com/questions/24997541/getting-the-memory-layout-out-of-an-avrelf-file-by-useing-python-pyelftools
        text_start = text_section.header['sh_addr']
        text_size = text_section.data_size

        new_data_region = (e_fptr.name, text_start, text_start + text_size)

        has_overlap, overlap_name = check_overlap(inserted_segments, new_data_region)
        if has_overlap:
            click.echo(
                f"FATAL: Overlap detected between .text section of '{new_data_region[0]}' and '{overlap_name}'.",
                err=True
            )
            raise SystemExit(1)

        ovmf[text_start - ovmf_file_start:text_start + text_size - ovmf_file_start] = text_section.data()
        inserted_segments.append(new_data_region)
        coquito_text_starts.append(text_start)

    # Find a suitable address to write the catalog to (a free 4KiB page)
    catalog_size = 1 << 12
    has_overlap = True
    catalog_start = ovmf_file_start

    for candidate in range(ovmf_file_start, ovmf_file_start + ovmf_file_size, catalog_size):
        tentative = ("catalog", candidate, candidate + catalog_size)
        has_overlap, _ = check_overlap(inserted_segments, tentative)
        if not has_overlap:
            catalog_start = candidate
            break

    if has_overlap:
        click.echo("FATAL: Failed to find a suitable spot to insert the image catalog in: file is too dense!", err=True)
        raise SystemExit(1)

    catalog = bytearray(catalog_size)

    # Align the header to an 8-byte boundary
    catalog_header = b'COQUITOcatalog'
    if len(catalog_header) % 8 != 0:
        catalog_header += b'\x00' * (8 - (len(catalog_header) % 8))
    catalog[:len(catalog_header)] = catalog_header

    addr_list_offset = len(catalog_header)

    # Write COQUITO .text start addresses (8 bytes each)
    for i, addr in enumerate(coquito_text_starts):
        catalog[addr_list_offset + i * 8:addr_list_offset + (i + 1) * 8] = int.to_bytes(
            addr, 8, byteorder='little', signed=False
        )

    # Finish with a nullptr terminator
    i = len(coquito_text_starts)
    catalog[addr_list_offset + i * 8:addr_list_offset + (i + 1) * 8] = int.to_bytes(
        0, 8, byteorder='little', signed=False
    )

    # Write the catalog page to the in-memory pseudo-OVMF file
    ovmf[catalog_start - ovmf_file_start:catalog_start + catalog_size - ovmf_file_start] = catalog

    # Flush the pseudo-OVMF file we just built to disk
    outfile.write(ovmf)

    click.echo(f"Successfully built '{outfile.name}'")
    for i, entry in enumerate(inserted_segments):
        e_name, e_start, e_end = entry
        click.echo(f"{e_name:<30}: {'CAT' if i >= 1 else '   '} 0x{e_start:x} -> 0x{e_end:x}")
    click.echo(f"Catalog is at 0x{catalog_start:x}")


# if __name__ == '__main__':
cli_entrypoint()