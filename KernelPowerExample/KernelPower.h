#pragma once
#include <Windows.h>

//
// KernelPower DLL Interface Specification
// ========================================
//
// KernelPower is a pluggable DLL that provides kernel memory read/write
// and execution primitives. Each implementation targets a specific exploit
// driver and encapsulates all driver-specific details (device symlink,
// IOCTL codes, data packet layout, etc.) internally.
//
// The host (DriverLoader) does NOT pass any driver handles or config to
// the DLL. The DLL opens the driver itself during KpInitialize().
//
// Lifecycle:
//   1. LoadLibrary("KernelPower.dll")
//   2. KpInitialize()  -- DLL opens driver, sets up internal state
//   3. KpGetTable()    -- get function pointer table
//   4. Call table->ReadPrimitive / WritePrimitive / TriggerExecute
//   5. KpCleanup()     -- DLL releases driver handle
//   6. FreeLibrary()
//
// Build: define KERNELPOWER_EXPORTS when building the DLL.
//

#ifdef KERNELPOWER_EXPORTS
#define KP_API __declspec(dllexport)
#else
#define KP_API __declspec(dllimport)
#endif

// Function table returned by KpGetTable(). All pointers are valid only
// after a successful KpInitialize() and before KpCleanup().
typedef struct _KP_FUNC_TABLE {

	// Read from kernel virtual address.
	//   target_addr: kernel VA to read from
	//   buffer:      caller-allocated output buffer
	//   size:        bytes to read
	//   returns:     TRUE on success, FALSE on failure
	BOOLEAN (*ReadPrimitive)(
		_In_  LPVOID target_addr,
		_Out_ LPVOID buffer,
		_In_  size_t size
	);

	// Write to kernel virtual address.
	//   target_addr: kernel VA to write to
	//   buffer:      source data
	//   size:        bytes to write
	//   returns:     TRUE on success, FALSE on failure
	BOOLEAN (*WritePrimitive)(
		_In_ LPVOID target_addr,
		_In_  LPVOID buffer,
		_In_  size_t size
	);

	// Trigger execution in the context of the exploit driver.
	// This causes the hooked driver to run the shellcode that was
	// previously written via WritePrimitive.
	//   returns:     TRUE on success, FALSE on failure
	BOOLEAN (*TriggerExecute)(
		void
	);

} KP_FUNC_TABLE;

#ifdef __cplusplus
extern "C" {
#endif

// Initialize the KernelPower DLL.
// The DLL opens the exploit driver device itself (no parameters needed).
// Must be called before KpGetTable() or any table function.
// Returns TRUE on success.
KP_API BOOL KpInitialize(void);

// Get the function pointer table.
// Only valid after KpInitialize() succeeds.
// Returns a pointer to a static table (caller must NOT free it).
KP_API const KP_FUNC_TABLE* KpGetTable(void);

// Release resources (close driver handle, etc.).
// After this call, all table function pointers become invalid.
KP_API VOID KpCleanup(void);

#ifdef __cplusplus
}
#endif
