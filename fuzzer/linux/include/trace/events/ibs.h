#undef TRACE_SYSTEM
#define TRACE_SYSTEM ibs

#if !defined(_IBS_LOGGER_H) || defined(TRACE_HEADER_MULTI_READ)
#define _IBS_LOGGER_H

#define IBS_F_LOAD (1u << 0)
#define IBS_F_STORE (1u << 1)
#define IBS_F_DCMISS (1u << 2)
#define IBS_F_UC (1u << 3)
#define IBS_F_WC (1u << 4)
#define IBS_F_BRNRET (1u << 5)
#define IBS_F_MICRO (1u << 6)
#define IBS_F_BRNFUSE (1u << 7)

#include <linux/tracepoint.h>

// TRACE event for IBS data
TRACE_EVENT(
	ibs_event,
	TP_PROTO(u64 rip, u64 uop_cnt, u64 phys, u64 lin, u8 mem_width,
		 u32 flags, u16 tag_to_ret, u16 comp_to_ret),

	TP_ARGS(rip, uop_cnt, phys, lin, mem_width, flags, tag_to_ret,
		comp_to_ret),

	TP_STRUCT__entry(__array(char, msg, 512)),

	TP_fast_assign(
		uint8_t is_load = flags & IBS_F_LOAD;
		uint8_t is_store = flags & IBS_F_STORE;
		uint8_t dc_miss = flags & IBS_F_DCMISS;
		uint8_t dc_uc_mem_acc = flags & IBS_F_UC;
		uint8_t dc_wc_mem_acc = flags & IBS_F_WC;
		uint8_t op_brn_ret = flags & IBS_F_BRNRET;
		uint8_t op_microcode = flags & IBS_F_MICRO;
		uint8_t op_brn_fuse = flags & IBS_F_BRNFUSE;

		const char *mw = (mem_width == 0)  ? "0" :
				 (mem_width == 1)  ? "1" :
				 (mem_width == 2)  ? "2" :
				 (mem_width == 3)  ? "4" :
				 (mem_width == 4)  ? "8" :
				 (mem_width == 5)  ? "16" :
				 (mem_width == 6)  ? "32" :
				 (mem_width == 7)  ? "64" :
				 (mem_width == 8)  ? "?8" :
				 (mem_width == 9)  ? "?9" :
				 (mem_width == 10) ? "?A" :
				 (mem_width == 11) ? "?B" :
				 (mem_width == 12) ? "?C" :
				 (mem_width == 13) ? "?D" :
				 (mem_width == 14) ? "?E" :
				 (mem_width == 15) ? "?F" :
						     "?";

		//RIP,uop_cnt,op_type,phys_addr,lin_addr,UC,WC,CacheMiss,Branch,tagToRetire,compToRetire,micro,multiOP
		if (is_load || is_store) {
			scnprintf(
				__entry->msg, sizeof(__entry->msg),
				"0x%016llx,%llu,%s%s,0x%016llx,0x%016llx,%s,%s,%s,,%u,%u,,\n",
				rip, uop_cnt, is_load ? "load" : "store", mw,
				phys, lin, dc_uc_mem_acc ? "True" : "False",
				dc_wc_mem_acc ? "True" : "False",
				dc_miss ? "True" : "False", tag_to_ret,
				comp_to_ret);
		} else {
			scnprintf(__entry->msg, sizeof(__entry->msg),
				  "0x%016llx,%llu,ALU,,,,,,%s,%u,%u,%s,%s\n",
				  rip, uop_cnt, op_brn_ret ? "True" : "False",
				  tag_to_ret, comp_to_ret,
				  op_microcode ? "True" : "False",
				  op_brn_fuse ? "True" : "False");
		}),

	TP_printk("%s", __entry->msg));

// Helper function to emit IBS trace events
TRACE_EVENT(ibs_marker, TP_PROTO(const char *msg, const u8 *bytes, u32 len),

	    TP_ARGS(msg, bytes, len),

	    TP_STRUCT__entry(__string(msg, msg) __field(u32, len)
				     __dynamic_array(u8, bytes, len)),

	    TP_fast_assign(__assign_str(msg); __entry->len = len;
			   memcpy(__get_dynamic_array(bytes), bytes, len);),

	    TP_printk("%s len=%u bytes=%s", __get_str(msg), __entry->len,
		      __print_hex(__get_dynamic_array(bytes), __entry->len)));

#endif /* _IBS_LOGGER_H */

#include <trace/define_trace.h>