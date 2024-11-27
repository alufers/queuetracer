from __future__ import print_function
from pathlib import Path
import sys
from typing import List, Optional
import dataclasses
import os 

from elftools.elf.elffile import ELFFile
from elftools.dwarf.die import DIE
from elftools.dwarf.compileunit import CompileUnit
from collections import defaultdict
from elftools.dwarf.locationlists import (
    LocationEntry, LocationExpr, LocationParser)
from elftools.dwarf.descriptions import (
    describe_DWARF_expr, set_global_machine_arch)
from elftools.dwarf.dwarf_expr import DWARFExprParser
from imgui_bundle import imgui, immapp, imgui_ctx, implot
import pylink
import pickle
import hashlib
import numpy as np
import time
import numpy.ma as ma

@dataclasses.dataclass
class ElfTracingInfo():
    modification_time: float = 0 # Cache invalidation
    embedders: List["EmbbeddedFieldInfo"] = dataclasses.field(default_factory=list)
    queue_definition_offsets: dict[str, int] = dataclasses.field(default_factory=dict)


def analyze_elf(filename) -> ElfTracingInfo:
    print("Processing file:", filename)
    elf_data = ElfTracingInfo()
    elf_data.modification_time = os.path.getmtime(filename)
    with open(filename, "rb") as f:
        elffile = ELFFile(f)

        if not elffile.has_dwarf_info():
            print("  file has no DWARF info")
            return
        # This is required for the descriptions module to correctly decode
        # register names contained in DWARF expressions.
        set_global_machine_arch(elffile.get_machine_arch())
        # get_dwarf_info returns a DWARFInfo context object, which is the
        # starting point for all DWARF-based processing in pyelftools.
        dwarfinfo = elffile.get_dwarf_info()

       
        
        for CU in dwarfinfo.iter_CUs():
            expr_parser = DWARFExprParser(CU.structs)

            # Start with the top DIE, the root for this CU's DIE tree
            top_DIE = CU.get_top_DIE()

            # print("CU: ", top_DIE.attributes.get('DW_AT_name').value)
            static_queue_type = find_StaticQueue_t(top_DIE)

            if static_queue_type:
                # print("Found StaticQueue_t in CU", top_DIE.attributes.get('DW_AT_name').value)

                # Find all the embedders of StaticQueue_t
                embedders = find_all_embedders_of_type(CU, static_queue_type, expr_parser)
                # print("Found StaticQueue_t in CU", top_DIE.attributes.get('DW_AT_name').value)
                # for embedder in embedders:
                #     if embedder.embedder_die.tag == "DW_TAG_variable":
                #         print("   ", embedder)
                elf_data.embedders.extend(embedders)
            
            queue_definition_type = find_QueueDefinition(top_DIE)
            if queue_definition_type:
                print("Found QueueDefinition in CU", top_DIE.attributes.get('DW_AT_name').value)
                offsets = get_struct_offsets(queue_definition_type)
                elf_data.queue_definition_offsets = offsets
    return elf_data





def run_on_file(filename):


    elf_data = analyze_elf(filename)
    print("Elf analysis done")
    jlink = pylink.JLink()
    jlink.open()

    # num_supported_devices = jlink.num_supported_devices()
    # for i in range(num_supported_devices):
    #     supported_device = jlink.supported_device(i)
    #     print(f"Supported device {i}: {supported_device}")
    # print("Supported devices: ", num_supported_devices)

    jlink.connect("MIMXRT1176xxxA_M7")
    enabled_queue_tracers = dict()
    for embedder in elf_data.embedders:
            enabled_queue_tracers[embedder.offset] = False

    PLOT_HISTORY_KEEP = 500
    queue_history = dict()
    queue_times = dict()
    for embedder in elf_data.embedders:
        queue_history[embedder.offset] = np.zeros(PLOT_HISTORY_KEEP)
        queue_times[embedder.offset] = np.zeros(PLOT_HISTORY_KEEP)

    pcHead_offset = elf_data.queue_definition_offsets.get("pcHead")

    assert pcHead_offset is not None, "pcHead not defined"
    uxMessagesWaiting_offset = elf_data.queue_definition_offsets.get("uxMessagesWaiting")
    assert uxMessagesWaiting_offset is not None, "uxMessagesWaiting not defined"

    uxItemSize_offset = elf_data.queue_definition_offsets.get("uxItemSize")
    uxLength_offset = elf_data.queue_definition_offsets.get("uxLength")
    assert uxItemSize_offset is not None and uxLength_offset is not None, "QueueDefinition should have uxItemSize and uxLength fields"


    SAMPLE_PERIOD = 1.0 / (100.0)

    actual_sample_rate = 0.0
    last_sample_time = time.time()

    jlink_info = f"num_available_breakpoints: {jlink.num_available_breakpoints(arm=True)}\nnum_available_watchpoints: {jlink.num_available_watchpoints()}"

    def gui_func():
        nonlocal enabled_queue_tracers
        nonlocal last_sample_time
        nonlocal queue_history
        nonlocal queue_times
        nonlocal actual_sample_rate

        imgui.text("Got jlink: "+ jlink.product_name)
        target_connected = jlink.target_connected()
        imgui.text("Target connected: "+ str(target_connected))
        imgui.text(f"Actual sample rate: {actual_sample_rate:.2f} Hz")
        imgui.text(jlink_info)

        should_sample = False
        now = time.time()
        if now - last_sample_time > SAMPLE_PERIOD:
            actual_sample_rate = 1.0 / (now - last_sample_time)
            should_sample = True
            last_sample_time = time.time()


        with imgui_ctx.begin_table(
            "QueuesTable", 4, imgui.TableFlags_.borders | imgui.TableFlags_.scroll_y
        ) as table:
            if table.visible:
                imgui.table_setup_column(
                    "Address", imgui.TableColumnFlags_.width_fixed, 100
                )
                imgui.table_setup_column("Name", imgui.TableColumnFlags_.width_stretch)
                imgui.table_setup_column("Value", imgui.TableColumnFlags_.width_stretch)
                imgui.table_setup_column("Plot", imgui.TableColumnFlags_.width_stretch)
                imgui.table_headers_row()
                for embedder in elf_data.embedders:
                    if embedder.embedder_die.tag == "DW_TAG_variable":
                        imgui.table_next_row()
                        imgui.table_set_column_index(0)
                        
                        _, enabled_queue_tracers[embedder.offset] = imgui.checkbox(
                             f"0x{embedder.offset:08x}", enabled_queue_tracers[embedder.offset])
                        
                        imgui.table_set_column_index(1)
                        imgui.text(embedder.path_name)
                        imgui.table_set_column_index(2)
                        if enabled_queue_tracers[embedder.offset]:
                            if should_sample:
                                
                                pcHead_addr = embedder.offset + pcHead_offset
                                uxMessagesWaiting_addr = embedder.offset + uxMessagesWaiting_offset
                                uxItemSize_addr = embedder.offset + uxItemSize_offset
                                uxLength_addr = embedder.offset + uxLength_offset
                               
                                if embedder.uxItemSize is None or embedder.uxLength is None:
                                    [pcHead_value] = jlink.memory_read32(
                                        addr=pcHead_addr, num_words=1
                                    )
                                    if pcHead_value > 0: # check if initialized
                                        embedder.uxItemSize = jlink.memory_read32(
                                            addr=uxItemSize_addr, num_words=1
                                        )[0]
                                        embedder.uxLength = jlink.memory_read32(
                                            addr=uxLength_addr, num_words=1
                                        )[0]
                                
                                if embedder.uxItemSize is not None and embedder.uxLength is not None:
                                    [uxMessagesWaiting_value] = jlink.memory_read32(
                                        addr=uxMessagesWaiting_addr, num_words=1
                                    )

                                    queue_history[embedder.offset] = np.roll(queue_history[embedder.offset], 1)
                                    queue_times[embedder.offset] = np.roll(queue_times[embedder.offset], 1)
                                    queue_history[embedder.offset][0] = float(uxMessagesWaiting_value)
                                    queue_times[embedder.offset][0] = time.time()
                            # end of sampling
                            if embedder.uxItemSize is not None and embedder.uxLength is not None:
                                imgui.text(f"Items: {queue_history[embedder.offset][0]}/{embedder.uxLength}")
                            else:
                                imgui.text("Not initialized")
                        else:
                            imgui.text("-")

                        imgui.table_set_column_index(3)
                        masked_times = ma.masked_equal(queue_times[embedder.offset], 0)
                        max_time =  masked_times.max() or 1
                        min_time = masked_times.min() or 0
                        imgui.text(f"min_time: {min_time:.2f} max_time: {max_time:.2f}")
                        if  enabled_queue_tracers[embedder.offset] and implot.begin_plot("plot_" + str(embedder.offset)):
                            implot.setup_axes(
                                "",
                                "",
                                implot.AxisFlags_.no_decorations,
                                0,  # implot.AxisFlags_.no_decorations,
                            )
                            
                            implot.setup_axes_limits(
                                min_time,
                                max_time,
                                0,
                                embedder.uxLength or 1,
                                imgui.Cond_.always,
                            )
                            implot.plot_line(
                                "Queue",
                                queue_times[embedder.offset],
                                queue_history[embedder.offset],
                            )
                            implot.end_plot()



                               

                                

                       
                        
    immapp.run(gui_function=gui_func, with_implot=True, fps_idle=100.0)

               


@dataclasses.dataclass
class EmbbeddedFieldInfo:
    """
    Holds info about an embedded type in e struct (possibly deeply).
    """

    embedder_die: DIE
    offset: int
    """
    The offset of the embedded type in the embedder.

    In case of:
        structs: The offset of the member in the struct + offset of any children embedders.
        variables: The absolute address of the variable + offset of any children embedders.
        typedefs: 0 + offset of any children embedders.
        arrays: For each element, the offset of the element in the array + offset of any children embedders.
    """
    path_name: str = ""
    type_name: Optional[str] = None
    byte_size: Optional[int] = None
    """
    The byte size of the embedder.
    """


    # Extra data for runtime
    uxLength: Optional[int] = None
    uxItemSize: Optional[int] = None

    def __repr__(self):
        return f"'{self.path_name}': 0x{self.offset:08x}"


def find_all_embedders_of_type(
    CU: CompileUnit, needle_die: DIE, expr_parser: DWARFExprParser
) -> List[EmbbeddedFieldInfo]:
    """
    DFS to find all the embedders of a type in a CU.

    Embedders are:
    - A struct that contains the type (directly or indirectly)
    - A typedef that aliases the type (directly or indirectly)
    - A non-external variable that contains the type (or another embedder)
    """
    top_DIE = CU.get_top_DIE()

    # Map of DIE offset -> embedded field info
    # One DIE can have multiple embedders (e.g. a struct with multiple fields of the needle type or an array)
    embedders_by_offset: defaultdict[int, List[EmbbeddedFieldInfo]] = defaultdict(list)
    already_walked = set()
    embedders_by_offset[needle_die.offset].append(EmbbeddedFieldInfo(needle_die, 0, "", needle_die.attributes.get("DW_AT_name").value.decode("utf-8")))
    already_walked.add(needle_die.offset)

    def walk_structure(d: DIE):
        name_attr = d.attributes.get("DW_AT_name")
        struct_name = "struct " + (name_attr.value.decode("utf-8") if name_attr else "<anon>")
        byte_size_attr = d.attributes.get("DW_AT_byte_size")
        byte_size = byte_size_attr.value if byte_size_attr else 0
        for child in d.iter_children():
            if child.tag == "DW_TAG_member":
                type_attr = child.attributes.get("DW_AT_type")
                offset_attr = child.attributes.get("DW_AT_data_member_location").value
                name_attr = child.attributes.get("DW_AT_name")
                # Note: anonymous unions might be missing DW_AT_name
                member_name = name_attr.value if name_attr else "<anon>"
                if isinstance(member_name, bytes):
                    member_name = member_name.decode("utf-8")
                member_type_die: Optional[DIE] = None
                if type_attr:
                    member_type_die = child.get_DIE_from_attribute("DW_AT_type")
               
                walk_die(member_type_die) # Walk the member type (DFS)

                # Now lets see if the type is an embedder (use get so we don't create an empty list)
                member_embedders = embedders_by_offset.get(member_type_die.offset) or []
                for member_embedder in member_embedders:
                    # Our member is a embedder, so we are too
                    embedders_by_offset[d.offset].append(EmbbeddedFieldInfo(
                        embedder_die=d,  # That's us
                        offset=offset_attr
                        + member_embedder.offset,  # Our member offset and the members internal offset
                        path_name=member_name
                        + (
                            f".{member_embedder.path_name}"
                            if member_embedder.path_name
                            else ""
                        ),
                        type_name= struct_name,
                        byte_size=byte_size,
                    ))

    def walk_typedef(d: DIE):
        name_attr = d.attributes.get("DW_AT_name")
        typedef_name = name_attr.value.decode("utf-8") if name_attr else "<anon>"

        # Get the aliased type
        type_attr = d.attributes.get("DW_AT_type")
        if type_attr:
            type_die = d.get_DIE_from_attribute("DW_AT_type")
            walk_die(type_die) # Walk the aliased type (DFS)
            embedders = embedders_by_offset.get(type_die.offset) or []
            # If the aliased type is an embedder, we are too
            for embedder in embedders:
                embedders_by_offset[d.offset].append(EmbbeddedFieldInfo(
                    embedder_die=d,
                    offset=embedder.offset, # Same offset as the aliased type
                    path_name=embedder.path_name,
                    type_name="typedef " + typedef_name,
                    byte_size=embedder.byte_size,
                ))
    def walk_variable(d: DIE):
        name_attr = d.attributes.get("DW_AT_name")
        variable_name = name_attr.value.decode("utf-8") if name_attr else "<anon>"

        external_attr = d.attributes.get("DW_AT_external")
        if external_attr:
            return  # We are not interested in external variables

        location_attr = d.attributes.get("DW_AT_location")
        if not location_attr or location_attr.form != "DW_FORM_exprloc":
            return
        
        # Crude variable address extraction (only works for simple cases, no relocation)
        var_addr: Optional[int] = None
        parsed_exprs = expr_parser.parse_expr(location_attr.value)
        if len(parsed_exprs) == 1 and parsed_exprs[0].op_name == "DW_OP_addr":
                var_addr = parsed_exprs[0].args[0]
        
        if var_addr is None:
            return
        # Get the type of the variable
        type_attr = d.attributes.get("DW_AT_type")
        if type_attr:
            type_die = d.get_DIE_from_attribute("DW_AT_type")
            walk_die(type_die)
            embedders = embedders_by_offset.get(type_die.offset) or []
           
            for embedder in embedders:
                embedders_by_offset[d.offset].append(EmbbeddedFieldInfo(
                    embedder_die=d,
                    offset=var_addr + embedder.offset, # Same offset as the embedder + our location
                    path_name=variable_name + "." + embedder.path_name,
                    type_name="variable " + variable_name,
                    byte_size=embedder.byte_size,
                ))
    def walk_array_type(d: DIE):
        upper_bound: Optional[int] = None
        for child in d.iter_children():
            if child.tag == "DW_TAG_subrange_type":
                upper_bound_attr = child.attributes.get("DW_AT_upper_bound")
                if upper_bound_attr:
                    upper_bound = upper_bound_attr.value
        type_attr = d.attributes.get("DW_AT_type")
        if type_attr and upper_bound:
            type_die = d.get_DIE_from_attribute("DW_AT_type")
            walk_die(type_die)
            embedders = embedders_by_offset.get(type_die.offset) or []
            # TODO: make N embedders for each element of the array
            for embedder in embedders:
                for i in range(upper_bound + 1): # Upper bound is inclusive
                    embedders_by_offset[d.offset].append(EmbbeddedFieldInfo(
                        embedder_die=d,
                        offset=embedder.offset + i * embedder.byte_size,  # Same offset as the embedder + the location of the array item
                        path_name=f"[{i}]{embedder.path_name}",
                        type_name="<array>",
                    ))
            




    def walk_die(d: DIE, iter_children_if_unknown=False):
        if d.offset in already_walked:
            return
        already_walked.add(d.offset)
        if d.tag == "DW_TAG_structure_type":
            walk_structure(d)
        elif d.tag == "DW_TAG_typedef":
            walk_typedef(d)
        elif d.tag == "DW_TAG_variable":
            walk_variable(d)
        elif d.tag == "DW_TAG_array_type":
            walk_array_type(d)
        else:
            for child in d.iter_children():
                walk_die(child)

    walk_die(top_DIE, True)
    return [embedder for embedders in embedders_by_offset.values() for embedder in embedders]


DIES_TO_OMIT_WHEN_SEARCHING_FOR_STATIC_QUEUE = {#
    # Don't recurs into these DIEs, because FreeRTOS defines the StaticQueue_t typedef in a global scope
    "DW_TAG_subprogram",
    "DW_TAG_enumeration_type",
    "DW_TAG_structure_type",
    "DW_TAG_union_type",
    "DW_TAG_array_type",
    "DW_TAG_namespace", # As it is a C typedef it cannot be in a namespace
    "DW_TAG_class_type",
    "DW_TAG_formal_parameter",
    "DW_TAG_pointer_type"
}


def find_StaticQueue_t(die: DIE) -> DIE:
    """A recursive function for that finds the DIE
    that represents the StaticQueue_t type.
    """

    # Let's not walk into some DIEs
    # This is not entirely accurate, but nobody defines StaticQueue_t in a function
    if die.tag in DIES_TO_OMIT_WHEN_SEARCHING_FOR_STATIC_QUEUE:
        # We are in a function, no need to go further
        return None
    if die.tag == "DW_TAG_typedef":
        name_attr = die.attributes.get("DW_AT_name")
        if name_attr:
            if name_attr.value == b"StaticQueue_t":
                # print(die)
                return die


    for child in die.iter_children():
        child_res = find_StaticQueue_t(child)
        if child_res:
            return child_res
        


DIES_TO_OMIT_WHEN_SEARCHING_FOR_QUEUE_DEFINITION = {#
    # Don't recurs into these DIEs, because FreeRTOS defines the StaticQueue_t typedef in a global scope
    "DW_TAG_subprogram",
    "DW_TAG_enumeration_type",
    "DW_TAG_union_type",
    "DW_TAG_array_type",
    "DW_TAG_namespace", # As it is a C typedef it cannot be in a namespace
    "DW_TAG_class_type",
    "DW_TAG_formal_parameter",
    "DW_TAG_pointer_type"
}

def find_QueueDefinition(die: DIE) -> DIE:
    """A recursive function for that finds the DIE
    that represents the QueueDefinition type. (The actual struct used by FreeRTOS internally)
    """

    # Let's not walk into some DIEs
    # This is not entirely accurate, but nobody defines StaticQueue_t in a function
    if die.tag in DIES_TO_OMIT_WHEN_SEARCHING_FOR_QUEUE_DEFINITION:
        # We are in a function, no need to go further
        return None
    if die.tag == "DW_TAG_structure_type":
        name_attr = die.attributes.get("DW_AT_name")
        declaration_attr = die.attributes.get("DW_AT_declaration")
        if name_attr and not declaration_attr:  
            if name_attr.value == b"QueueDefinition":
                print(die)
                return die


    for child in die.iter_children():
        child_res = find_QueueDefinition(child)
        if child_res:
            return child_res

def get_struct_offsets(die: DIE) -> dict[str, int]:
    """
    A function that returns the offsets of the fields of a struct.
    """
    assert die.tag == "DW_TAG_structure_type", "This function only works on structs"
    offsets = {}
    for child in die.iter_children():
        if child.tag == "DW_TAG_member":
            offset_attr = child.attributes.get("DW_AT_data_member_location")
            name_attr = child.attributes.get("DW_AT_name")
            if offset_attr and name_attr:
                offsets[name_attr.value.decode("utf-8")] = offset_attr.value
    return offsets


ELF_DATA_CACHE = "elf_cache"
def analyze_elf_cached(filename) -> ElfTracingInfo:
    path_sha = hashlib.sha256(filename.encode()).hexdigest()
    cache_file = os.path.join(ELF_DATA_CACHE, path_sha + ".pkl")
    modif_time = None
    if os.path.exists(cache_file):
        
        with open(cache_file, "rb") as f:
            elf_data = pickle.load(f)
    if not modif_time or modif_time < os.path.getmtime(filename):
        elf_data = analyze_elf(filename)
        os.makedirs(ELF_DATA_CACHE, exist_ok=True)
        with open(cache_file, "wb") as f:
            pickle.dump(elf_data, f)
    return elf_data


# def debug_signal_handler(signal, frame):
#     import pdb
#     pdb.set_trace()
# import signal
# signal.signal(signal.SIGINT, debug_signal_handler)

def main():
    run_on_file(sys.argv[1])

if __name__ == "__main__":
    main()
