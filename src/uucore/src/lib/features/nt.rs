// This file is part of the uutils coreutils package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Windows NT API helpers with RAII wrappers.

use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::{io::Error, mem::MaybeUninit};

use crate::error::{UResult, USimpleError};

use windows_sys::Win32::Foundation::NTSTATUS;
use windows_sys::Win32::Security::{
    GROUP_SECURITY_INFORMATION, GetFileSecurityW, GetLengthSid, LookupAccountSidW,
    OWNER_SECURITY_INFORMATION, PSID, SidTypeUnknown,
};

pub const SYNCHRONIZE: u32 = 0x00100000;
pub const FILE_SHARE_READ: u32 = 0x00000001;
pub const FILE_SHARE_WRITE: u32 = 0x00000002;
pub const FILE_SHARE_DELETE: u32 = 0x00000004;
pub const FILE_DIRECTORY_FILE: u32 = 0x00000001;
pub const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;
pub const FILE_OPEN_FOR_FREE_SPACE_QUERY: u32 = 0x00800000;

const OBJ_CASE_INSENSITIVE: u32 = 0x00000040;

pub const FILE_REMOTE_DEVICE: u32 = 0x00000010;

#[allow(non_upper_case_globals)]
pub const FileFsDeviceInformation: u32 = 4;
#[allow(non_upper_case_globals)]
pub const FileFsAttributeInformation: u32 = 5;
#[allow(non_upper_case_globals)]
pub const FileFsFullSizeInformation: u32 = 7;
#[allow(non_upper_case_globals)]
pub const FileIdInformation: u32 = 59;

#[repr(C)]
pub struct FILE_FS_DEVICE_INFORMATION {
    pub device_type: u32,
    pub characteristics: u32,
}

#[repr(C)]
pub struct FILE_FS_ATTRIBUTE_INFORMATION {
    pub file_system_attributes: u32,
    pub maximum_component_name_length: i32,
    pub file_system_name_length: u32,
    pub file_system_name: [u16; 128],
}

#[repr(C)]
pub struct FILE_FS_FULL_SIZE_INFORMATION {
    pub total_allocation_units: i64,
    pub caller_available_allocation_units: i64,
    pub actual_available_allocation_units: i64,
    pub sectors_per_allocation_unit: u32,
    pub bytes_per_sector: u32,
}

#[repr(C)]
pub struct FILE_ID_INFORMATION {
    pub volume_serial_number: u64,
    pub file_id: [u8; 16],
}

#[repr(C)]
struct UNICODE_STRING {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct OBJECT_ATTRIBUTES {
    length: u32,
    root_directory: *mut std::ffi::c_void,
    object_name: *const UNICODE_STRING,
    attributes: u32,
    security_descriptor: *mut std::ffi::c_void,
    security_quality_of_service: *mut std::ffi::c_void,
}

#[repr(C)]
struct IO_STATUS_BLOCK {
    status: NTSTATUS,
    information: usize,
}

unsafe extern "system" {
    fn NtOpenFile(
        file_handle: *mut *mut std::ffi::c_void,
        desired_access: u32,
        object_attributes: *const OBJECT_ATTRIBUTES,
        io_status_block: *mut IO_STATUS_BLOCK,
        share_access: u32,
        open_options: u32,
    ) -> NTSTATUS;

    fn NtClose(handle: *mut std::ffi::c_void) -> NTSTATUS;

    fn NtQueryInformationFile(
        file_handle: *mut std::ffi::c_void,
        io_status_block: *mut IO_STATUS_BLOCK,
        file_information: *mut std::ffi::c_void,
        length: u32,
        file_information_class: u32,
    ) -> NTSTATUS;

    fn NtQueryVolumeInformationFile(
        file_handle: *mut std::ffi::c_void,
        io_status_block: *mut IO_STATUS_BLOCK,
        fs_information: *mut std::ffi::c_void,
        length: u32,
        fs_information_class: u32,
    ) -> NTSTATUS;

    fn RtlDosPathNameToNtPathName_U(
        dos_file_name: *const u16,
        nt_file_name: *mut UNICODE_STRING,
        file_part: *mut *mut u16,
        reserved: *mut std::ffi::c_void,
    ) -> u8;

    fn RtlFreeUnicodeString(unicode_string: *mut UNICODE_STRING);
}

#[repr(transparent)]
pub struct NtHandle(*mut std::ffi::c_void);

impl Drop for NtHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { NtClose(self.0) };
        }
    }
}

#[repr(transparent)]
struct UnicodeString(UNICODE_STRING);

impl UnicodeString {
    fn empty() -> Self {
        Self(UNICODE_STRING {
            length: 0,
            maximum_length: 0,
            buffer: ptr::null_mut(),
        })
    }
}

impl Drop for UnicodeString {
    fn drop(&mut self) {
        if !self.0.buffer.is_null() {
            unsafe { RtlFreeUnicodeString(&raw mut self.0) };
        }
    }
}

fn to_wide_null(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

/// Opens a file or directory via `NtOpenFile`.
///
/// The file is opened with full share access (`READ | WRITE | DELETE`).
pub fn open_file(path: &Path, desired_access: u32, open_options: u32) -> UResult<NtHandle> {
    let wide = to_wide_null(path);
    let mut nt_path = UnicodeString::empty();
    if unsafe {
        RtlDosPathNameToNtPathName_U(
            wide.as_ptr(),
            &raw mut nt_path.0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(USimpleError::new(
            1,
            format!(
                "RtlDosPathNameToNtPathName_U failed: {}",
                Error::last_os_error()
            ),
        ));
    }

    let attr = OBJECT_ATTRIBUTES {
        length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        root_directory: ptr::null_mut(),
        object_name: &nt_path.0,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: ptr::null_mut(),
        security_quality_of_service: ptr::null_mut(),
    };
    let mut handle = ptr::null_mut();
    let mut iosb = MaybeUninit::<IO_STATUS_BLOCK>::uninit();
    let status = unsafe {
        NtOpenFile(
            &raw mut handle,
            desired_access,
            &attr,
            iosb.as_mut_ptr(),
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            open_options,
        )
    };
    if status < 0 {
        return Err(USimpleError::new(
            1,
            format!("NtOpenFile failed: 0x{:08X}", status as u32),
        ));
    }
    Ok(NtHandle(handle))
}

/// Queries volume information for the file associated with the given handle.
///
/// # Safety
///
/// `T` must be the correct struct for the given `information_class`.
pub unsafe fn query_volume_information<T>(handle: &NtHandle, information_class: u32) -> UResult<T> {
    let mut info = MaybeUninit::<T>::uninit();
    let mut iosb = MaybeUninit::<IO_STATUS_BLOCK>::uninit();
    let status = unsafe {
        NtQueryVolumeInformationFile(
            handle.0,
            iosb.as_mut_ptr(),
            info.as_mut_ptr().cast(),
            size_of::<T>() as u32,
            information_class,
        )
    };
    if status < 0 {
        return Err(USimpleError::new(
            1,
            format!(
                "NtQueryVolumeInformationFile failed: 0x{:08X}",
                status as u32
            ),
        ));
    }
    Ok(unsafe { info.assume_init() })
}

/// Queries file information for the given handle.
///
/// # Safety
///
/// `T` must be the correct struct for the given `information_class`.
pub unsafe fn query_information_file<T>(handle: &NtHandle, information_class: u32) -> UResult<T> {
    let mut info = MaybeUninit::<T>::uninit();
    let mut iosb = MaybeUninit::<IO_STATUS_BLOCK>::uninit();
    let status = unsafe {
        NtQueryInformationFile(
            handle.0,
            iosb.as_mut_ptr(),
            info.as_mut_ptr().cast(),
            size_of::<T>() as u32,
            information_class,
        )
    };
    if status < 0 {
        return Err(USimpleError::new(
            1,
            format!("NtQueryInformationFile failed: 0x{:08X}", status as u32),
        ));
    }
    Ok(unsafe { info.assume_init() })
}

pub const SECURITY_MAX_SID_SIZE: usize = 68;
pub const SECURITY_MAX_SID_STRING_CHARACTERS: usize = 187;

pub type Sid = [u8; SECURITY_MAX_SID_SIZE];

#[repr(C)]
struct SECURITY_DESCRIPTOR_RELATIVE {
    revision: u8,
    sbz1: u8,
    control: u16,
    owner: u32,
    group: u32,
    sacl: u32,
    dacl: u32,
}

/// # Safety
/// `sd` must point to a valid self-relative security descriptor.
/// `offset` must be a valid SID offset within it, or 0.
unsafe fn sd_sid_to_fixed(sd: *const SECURITY_DESCRIPTOR_RELATIVE, offset: u32) -> Sid {
    let mut buf = [0u8; SECURITY_MAX_SID_SIZE];

    if offset != 0 {
        let psid = unsafe { (sd as *const u8).add(offset as usize) } as PSID;
        let len = unsafe { GetLengthSid(psid) } as usize;
        unsafe { ptr::copy_nonoverlapping(psid as *const u8, buf.as_mut_ptr(), len) };
    }

    buf
}

/// Resolves a SID to an account name via `LookupAccountSidW`.
pub fn resolve_sid_to_name(psid: PSID) -> Option<String> {
    let mut name_buf = [0u16; SECURITY_MAX_SID_STRING_CHARACTERS];
    let mut domain_buf = [0u16; SECURITY_MAX_SID_STRING_CHARACTERS];
    let mut name_len: u32 = name_buf.len() as u32;
    let mut domain_len: u32 = domain_buf.len() as u32;
    let mut sid_use = SidTypeUnknown;

    let ok = unsafe {
        LookupAccountSidW(
            ptr::null(),
            psid,
            name_buf.as_mut_ptr(),
            &mut name_len,
            domain_buf.as_mut_ptr(),
            &mut domain_len,
            &mut sid_use,
        )
    };

    if ok == 0 {
        return None;
    }

    Some(String::from_utf16_lossy(&name_buf[..name_len as usize]))
}

#[derive(Debug)]
pub struct OwnerGroup {
    pub owner_sid: Sid,
    pub group_sid: Sid,
}

/// Retrieves owner and group SIDs via `GetFileSecurityW` into a
/// stack-allocated buffer. Returns `None` on failure.
pub fn path_to_owner_and_group(path: &Path) -> Option<OwnerGroup> {
    // The buffer must be u32-aligned for SECURITY_DESCRIPTOR_RELATIVE.
    #[repr(C)]
    struct SdBuf {
        sd: SECURITY_DESCRIPTOR_RELATIVE,
        sids: [u8; 2 * SECURITY_MAX_SID_SIZE],
    }

    let wide_path = to_wide_null(path);
    let mut buf = MaybeUninit::<SdBuf>::uninit();
    let mut needed: u32 = 0;

    if unsafe {
        GetFileSecurityW(
            wide_path.as_ptr(),
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
            buf.as_mut_ptr().cast(),
            size_of::<SdBuf>() as u32,
            &mut needed,
        )
    } == 0
    {
        return None;
    }

    let sd = buf.as_ptr().cast::<SECURITY_DESCRIPTOR_RELATIVE>();

    Some(OwnerGroup {
        owner_sid: unsafe { sd_sid_to_fixed(sd, (*sd).owner) },
        group_sid: unsafe { sd_sid_to_fixed(sd, (*sd).group) },
    })
}
