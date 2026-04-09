#include "NTUndocumented.h"
#include "ProcessLister.h"
#include "UserModeBridge.h"
#include <wdf.h>

DRIVER_INITIALIZE DriverEntry;
#pragma alloc_text(INIT, DriverEntry)

UNICODE_STRING deviceName, symLink;
PDEVICE_OBJECT deviceObject;

static ULONG   g_DseCount = 0;
static PULONG  g_DseAddrs[DSE_MAX_ADDRS] = {0};
static ULONG   g_DseOrig[DSE_MAX_ADDRS] = {0};

static void DseWriteAll(ULONG val)
{
	KIRQL irql;
	ULONG64 cr0;
	ULONG i;
	KeRaiseIrql(DISPATCH_LEVEL, &irql);
	cr0 = __readcr0();
	__writecr0(cr0 & ~(1ULL << 16));
	for (i = 0; i < g_DseCount; i++)
	{
		if (g_DseAddrs[i] && MmIsAddressValid(g_DseAddrs[i]))
			*g_DseAddrs[i] = val;
	}
	__writecr0(cr0);
	KeLowerIrql(irql);
}

NTSTATUS CopyVirtualMemory(PEPROCESS targetProcess, PVOID sourceAddress, PVOID targetAddress, SIZE_T size)
{
	PSIZE_T readBytes;
	return MmCopyVirtualMemory(targetProcess, sourceAddress, PsGetCurrentProcess(), targetAddress, size, UserMode, &readBytes);
}

NTSTATUS WriteVirtualMemory(PEPROCESS targetProcess, PVOID sourceAddress, PVOID targetAddress, SIZE_T size)
{
	KAPC_STATE apcState;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PMDL mdl;
	PVOID mapped;
	PVOID kernelBuf;

	/* 先在当前进程上下文拷贝用户数据到内核池 */
	kernelBuf = ExAllocatePool(NonPagedPool, size);
	if (!kernelBuf) return STATUS_INSUFFICIENT_RESOURCES;
	RtlCopyMemory(kernelBuf, sourceAddress, size);

	/* 切到目标进程, 用 MDL 映射目标页为可写 */
	KeStackAttachProcess((PKPROCESS)targetProcess, &apcState);

	mdl = IoAllocateMdl(targetAddress, (ULONG)size, FALSE, FALSE, NULL);
	if (mdl)
	{
		__try
		{
			MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			IoFreeMdl(mdl);
			KeUnstackDetachProcess(&apcState);
			ExFreePool(kernelBuf);
			return STATUS_ACCESS_VIOLATION;
		}

		mapped = MmMapLockedPagesSpecifyCache(
			mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

		if (mapped)
		{
			status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
			if (NT_SUCCESS(status))
			{
				RtlCopyMemory(mapped, kernelBuf, size);
			}
			MmUnmapLockedPages(mapped, mdl);
		}

		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
	}

	KeUnstackDetachProcess(&apcState);
	ExFreePool(kernelBuf);
	return status;
}

NTSTATUS UnsupportedDispatch(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

NTSTATUS CreateDispatch(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

NTSTATUS CloseDispatch(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

//NTSTATUS Unload(IN PDRIVER_OBJECT DriverObject)
//{
//	IoDeleteSymbolicLink(&symLink);
//	IoDeleteDevice(DriverObject->DeviceObject);
//}

NTSTATUS Unload(IN PDRIVER_OBJECT DriverObject)
{
	IoDeleteSymbolicLink(&symLink);
	IoDeleteSymbolicLink(&deviceName);
	IoDeleteDevice(deviceObject);
	return ZwUnloadDriver(&deviceName);
}

NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS status;
	ULONG bytesIO = 0;
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;

	if (controlCode == IO_COPY_MEMORY)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_COPY_MEMORY_OPERATION))
		{
			PKERNEL_COPY_MEMORY_OPERATION request = (PKERNEL_COPY_MEMORY_OPERATION)Irp->AssociatedIrp.SystemBuffer;
			PEPROCESS targetProcess;

			if (NT_SUCCESS(PsLookupProcessByProcessId(request->targetProcessId, &targetProcess)))
			{
				CopyVirtualMemory(targetProcess, request->targetAddress, request->bufferAddress, request->bufferSize);
				ObDereferenceObject(targetProcess);
			}

			status = STATUS_SUCCESS;
			bytesIO = sizeof(KERNEL_COPY_MEMORY_OPERATION);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_GET_PROCESS_LIST)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_PROCESS_LIST_OPERATION) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(KERNEL_PROCESS_LIST_OPERATION))
		{
			PKERNEL_PROCESS_LIST_OPERATION request = (PKERNEL_PROCESS_LIST_OPERATION)Irp->AssociatedIrp.SystemBuffer;

			GetProcessList(request->bufferAddress, request->bufferSize, &request->bufferSize, &request->processCount);

			status = STATUS_SUCCESS;
			bytesIO = sizeof(KERNEL_PROCESS_LIST_OPERATION);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_WRITE_MEMORY)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_COPY_MEMORY_OPERATION))
		{
			PKERNEL_COPY_MEMORY_OPERATION request = (PKERNEL_COPY_MEMORY_OPERATION)Irp->AssociatedIrp.SystemBuffer;
			PEPROCESS targetProcess;

			if (NT_SUCCESS(PsLookupProcessByProcessId(request->targetProcessId, &targetProcess)))
			{
				WriteVirtualMemory(targetProcess, request->bufferAddress, request->targetAddress, request->bufferSize);
				ObDereferenceObject(targetProcess);
			}

			status = STATUS_SUCCESS;
			bytesIO = sizeof(KERNEL_COPY_MEMORY_OPERATION);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_READ_KERNEL)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(KERNEL_READ_KERNEL_OPERATION))
		{
			PKERNEL_READ_KERNEL_OPERATION request = (PKERNEL_READ_KERNEL_OPERATION)Irp->AssociatedIrp.SystemBuffer;
			PVOID src = (PVOID)(ULONG_PTR)request->kernelAddress;
			if (MmIsAddressValid(src) && request->bufferSize > 0 && request->bufferSize <= 0x100000)
			{
				__try
				{
					RtlCopyMemory(request->bufferAddress, src, request->bufferSize);
					status = STATUS_SUCCESS;
					bytesIO = sizeof(KERNEL_READ_KERNEL_OPERATION);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					status = STATUS_ACCESS_VIOLATION;
					bytesIO = 0;
				}
			}
			else { status = STATUS_INVALID_PARAMETER; bytesIO = 0; }
		}
		else { status = STATUS_INFO_LENGTH_MISMATCH; bytesIO = 0; }
	}
	else if (controlCode == IO_UNLOAD_DRIVER)
	{
		/* 先完成 IRP, 再清理资源 */
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		IoDeleteSymbolicLink(&symLink);
		IoDeleteDevice(deviceObject);
		return STATUS_SUCCESS;
	}
	else if (controlCode == IO_DSE_SET_ADDR)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(KERNEL_DSE_OPERATION))
		{
			PKERNEL_DSE_OPERATION request = (PKERNEL_DSE_OPERATION)Irp->AssociatedIrp.SystemBuffer;
			ULONG i;
			g_DseCount = 0;
			for (i = 0; i < request->count && i < DSE_MAX_ADDRS; i++)
			{
				PULONG p = (PULONG)(ULONG_PTR)request->addresses[i];
				if (MmIsAddressValid(p))
				{
					ULONG val = *p;
					g_DseAddrs[g_DseCount] = p;
					g_DseOrig[g_DseCount] = (val != 0) ? val : 6;
					request->originals[i] = val;
					g_DseCount++;
				}
			}
			request->count = g_DseCount;
			status = g_DseCount > 0 ? STATUS_SUCCESS : STATUS_NOT_FOUND;
			bytesIO = sizeof(KERNEL_DSE_OPERATION);
		}
		else { status = STATUS_INFO_LENGTH_MISMATCH; bytesIO = 0; }
	}
	else if (controlCode == IO_DSE_DISABLE)
	{
		if (g_DseCount > 0)
		{ DseWriteAll(0); status = STATUS_SUCCESS; }
		else status = STATUS_DEVICE_NOT_READY;
		bytesIO = 0;
	}
	else if (controlCode == IO_DSE_ENABLE)
	{
		if (g_DseCount > 0)
		{
			KIRQL irql; ULONG64 cr0; ULONG i;
			KeRaiseIrql(DISPATCH_LEVEL, &irql);
			cr0 = __readcr0();
			__writecr0(cr0 & ~(1ULL << 16));
			for (i = 0; i < g_DseCount; i++)
				if (g_DseAddrs[i] && MmIsAddressValid(g_DseAddrs[i]))
					*g_DseAddrs[i] = g_DseOrig[i];
			__writecr0(cr0);
			KeLowerIrql(irql);
			status = STATUS_SUCCESS;
		}
		else status = STATUS_DEVICE_NOT_READY;
		bytesIO = 0;
	}
	else if (controlCode == IO_DSE_QUERY)
	{
		if (stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(KERNEL_DSE_OPERATION))
		{
			PKERNEL_DSE_OPERATION request = (PKERNEL_DSE_OPERATION)Irp->AssociatedIrp.SystemBuffer;
			ULONG i;
			request->count = g_DseCount;
			for (i = 0; i < g_DseCount && i < DSE_MAX_ADDRS; i++)
			{
				request->addresses[i] = (ULONG64)(ULONG_PTR)g_DseAddrs[i];
				request->originals[i] = (g_DseAddrs[i] && MmIsAddressValid(g_DseAddrs[i])) ? *g_DseAddrs[i] : 0xDEAD;
			}
			status = STATUS_SUCCESS;
			bytesIO = sizeof(KERNEL_DSE_OPERATION);
		}
		else { status = STATUS_BUFFER_TOO_SMALL; bytesIO = 0; }
	}
	else
	{
		status = STATUS_INVALID_PARAMETER;
		bytesIO = 0;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = bytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS DriverInitialize(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	

	UNREFERENCED_PARAMETER(RegistryPath);

	RtlInitUnicodeString(&deviceName, L"\\Device\\KsDumper");
	RtlInitUnicodeString(&symLink, L"\\DosDevices\\KsDumper");

	status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);

	if (!NT_SUCCESS(status))
	{
		return status;
	}
	status = IoCreateSymbolicLink(&symLink, &deviceName);

	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(deviceObject);
		return status;
	}
	deviceObject->Flags |= DO_BUFFERED_IO;

	for (ULONG t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
		DriverObject->MajorFunction[t] = &UnsupportedDispatch;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = &CreateDispatch;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = &CloseDispatch;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &IoControl;
	DriverObject->DriverUnload = &Unload;
	deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	return status;
}



NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	return IoCreateDriver(NULL, &DriverInitialize);
}
