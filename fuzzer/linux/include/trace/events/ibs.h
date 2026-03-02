#undef TRACE_SYSTEM
#define TRACE_SYSTEM ibs

#if !defined(_IBS_LOGGER_H) || defined(TRACE_HEADER_MULTI_READ)
#define _IBS_LOGGER_H

#include <linux/tracepoint.h>

// TRACE event for IBS data
TRACE_EVENT(
	ibs_event,
	TP_PROTO(u64 rip, u64 uop_cnt, u64 phys, u64 lin, u8 is_load,
		 u8 is_store, u8 mem_width, u8 dc_miss, u8 uc, u8 wc,
		 u16 tag_to_ret, u16 comp_to_ret),

	TP_ARGS(rip, uop_cnt, phys, lin, is_load, is_store, mem_width, dc_miss,
		uc, wc, tag_to_ret, comp_to_ret),

	TP_STRUCT__entry(
		__field(u64, rip) __field(u64, uop_cnt) __field(u64, phys)
			__field(u64, lin) __field(u8, is_load) __field(
				u8, is_store) __field(u8, mem_width)
				__field(u8, dc_miss) __field(u8, uc)
					__field(u8, wc) __field(u16, tag_to_ret)
						__field(u16, comp_to_ret)),

	TP_fast_assign(__entry->rip = rip; __entry->uop_cnt = uop_cnt;
		       __entry->phys = phys; __entry->lin = lin;
		       __entry->is_load = is_load; __entry->is_store = is_store;
		       __entry->mem_width = mem_width;
		       __entry->dc_miss = dc_miss; __entry->uc = uc;
		       __entry->wc = wc; __entry->tag_to_ret = tag_to_ret;
		       __entry->comp_to_ret = comp_to_ret;),

	TP_printk(
		"rip=0x%016llx uop=%llu %s%s mw=%u phys=0x%016llx lin=0x%016llx miss=%u uc=%u wc=%u tag=%u comp=%u",
		__entry->rip, __entry->uop_cnt, __entry->is_load ? "L" : "",
		__entry->is_store ? "S" : "", __entry->mem_width, __entry->phys,
		__entry->lin, __entry->dc_miss, __entry->uc, __entry->wc,
		__entry->tag_to_ret, __entry->comp_to_ret));

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