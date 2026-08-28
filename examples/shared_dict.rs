#![no_std]

use core::alloc::Layout;
use core::cmp::Ordering;
use core::ffi::{c_char, c_void};
use core::fmt::Write;
use core::mem;
use core::ptr::{self, NonNull};
use core::slice;

use nginx_sys::{
    NGX_CONF_TAKE2, NGX_HTTP_DELETE, NGX_HTTP_MAIN_CONF, NGX_HTTP_MAIN_CONF_OFFSET,
    NGX_HTTP_MODULE, NGX_LOG_EMERG, ngx_command_t, ngx_conf_t, ngx_http_compile_complex_value_t,
    ngx_http_complex_value, ngx_http_complex_value_t, ngx_http_module_t, ngx_int_t, ngx_module_t,
    ngx_parse_size, ngx_pool_t, ngx_queue_t, ngx_rbt_red, ngx_rbtree_key_t, ngx_rbtree_node_t,
    ngx_rbtree_t, ngx_shared_memory_add, ngx_shm_zone_t, ngx_str_t, ngx_uint_t,
};
use ngx::collections::{SlabQueue, SlabQueueEntry, SlabRbTree, SlabRbTreeEntry};
use ngx::core::{
    ModuleDescriptor, NGX_CONF_ERROR, NGX_CONF_OK, NgxStr, NgxString, Pool, SlabGuard, SlabPool,
    SlabRegion, Status,
};
use ngx::http::{
    HttpConfigurationParser, HttpModule, HttpModuleMainConf, HttpVariableFlags,
    HttpVariableHandler, HttpVariableOutput, HttpVariableSetter, HttpVariableValueRef,
    RequestRefMut, add_variable_with_setter,
};
use ngx::{ngx_conf_log_error, ngx_log_debug, ngx_string};

struct HttpSharedDictModule;

unsafe impl HttpModule for HttpSharedDictModule {
    fn module() -> ModuleDescriptor {
        unsafe { ModuleDescriptor::from_raw(&raw mut ngx_http_shared_dict_module) }
            .expect("ngx_http_shared_dict_module descriptor")
    }

    fn preconfigure(parser: &mut HttpConfigurationParser<'_>) -> ngx_int_t {
        if add_variable_with_setter::<SharedDictEntriesVariable, SharedDictEntriesVariable>(
            parser,
            NgxStr::from_bytes(b"shared_dict_entries"),
            HttpVariableFlags::CHANGEABLE | HttpVariableFlags::NOCACHEABLE,
            0,
        )
        .is_err()
        {
            return Status::NGX_ERROR.0;
        }
        Status::NGX_OK.0
    }
}

unsafe impl HttpModuleMainConf for HttpSharedDictModule {
    type MainConf = SharedDictMainConfig;
}

static mut NGX_HTTP_SHARED_DICT_COMMANDS: [ngx_command_t; 3] = [
    ngx_command_t {
        name: ngx_string!("shared_dict_zone"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE2) as ngx_uint_t,
        set: Some(ngx_http_shared_dict_add_zone),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("shared_dict"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE2) as ngx_uint_t,
        set: Some(ngx_http_shared_dict_add_variable),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t::empty(),
];

static NGX_HTTP_SHARED_DICT_MODULE_CTX: ngx_http_module_t = ngx_http_module_t {
    preconfiguration: Some(ngx::http::preconfiguration::<HttpSharedDictModule>),
    postconfiguration: None,
    create_main_conf: Some(HttpSharedDictModule::create_main_conf),
    init_main_conf: None,
    create_srv_conf: None,
    merge_srv_conf: None,
    create_loc_conf: None,
    merge_loc_conf: None,
};

#[cfg(feature = "export-modules")]
ngx::ngx_modules!(ngx_http_shared_dict_module);

#[used]
#[allow(non_upper_case_globals)]
#[cfg_attr(not(feature = "export-modules"), unsafe(no_mangle))]
pub static mut ngx_http_shared_dict_module: ngx_module_t = ngx_module_t {
    ctx: &raw const NGX_HTTP_SHARED_DICT_MODULE_CTX as _,
    commands: unsafe { &raw mut NGX_HTTP_SHARED_DICT_COMMANDS[0] },
    type_: NGX_HTTP_MODULE as _,
    ..ngx_module_t::default()
};

/// Persistent root stored in `ngx_slab_pool_t::data` and reused on nginx reload.
#[repr(C)]
struct SharedDictState {
    tree: ngx_rbtree_t,
    sentinel: ngx_rbtree_node_t,
    queue: ngx_queue_t,
    entries: usize,
}

/// Persistent record with key bytes followed immediately by value bytes.
#[repr(C)]
struct SharedDictEntry {
    tree: ngx_rbtree_node_t,
    queue: ngx_queue_t,
    key_len: usize,
    value_len: usize,
}

unsafe impl SlabRbTreeEntry for SharedDictEntry {
    type Payload = ();

    unsafe fn from_rbtree_node(node: NonNull<ngx_rbtree_node_t>) -> NonNull<Self> {
        node.cast()
    }

    unsafe fn rbtree_node(entry: NonNull<Self>) -> NonNull<ngx_rbtree_node_t> {
        entry.cast()
    }

    unsafe fn payload(entry: NonNull<Self>) -> NonNull<Self::Payload> {
        entry.cast()
    }
}

unsafe impl SlabQueueEntry for SharedDictEntry {
    type Payload = ();

    unsafe fn from_queue(queue: NonNull<ngx_queue_t>) -> NonNull<Self> {
        let entry = unsafe {
            queue.as_ptr().byte_sub(mem::offset_of!(Self, queue)).cast::<SharedDictEntry>()
        };
        unsafe { NonNull::new_unchecked(entry) }
    }

    unsafe fn queue_node(entry: NonNull<Self>) -> NonNull<ngx_queue_t> {
        unsafe { NonNull::new_unchecked(ptr::addr_of_mut!((*entry.as_ptr()).queue)) }
    }

    unsafe fn payload(entry: NonNull<Self>) -> NonNull<Self::Payload> {
        entry.cast()
    }
}

#[derive(Debug)]
struct SharedDictMainConfig {
    shm_zone: *mut ngx_shm_zone_t,
}

impl Default for SharedDictMainConfig {
    fn default() -> Self {
        Self { shm_zone: ptr::null_mut() }
    }
}

impl SharedDictMainConfig {
    fn shm_zone(&self) -> Option<&ngx_shm_zone_t> {
        unsafe { self.shm_zone.as_ref() }
    }
}

fn variable_name(name: ngx_str_t) -> Option<ngx_str_t> {
    let name = name.strip_prefix(b"$")?;
    (!name.is_empty()).then_some(name)
}

fn shared_dict_hash(key: &[u8]) -> ngx_rbtree_key_t {
    key.iter().fold(0_u32, |hash, byte| hash.wrapping_mul(31).wrapping_add((*byte).into()))
        as ngx_rbtree_key_t
}

unsafe fn shared_dict_state_tree(state: NonNull<SharedDictState>) -> NonNull<ngx_rbtree_t> {
    unsafe { NonNull::new_unchecked(ptr::addr_of_mut!((*state.as_ptr()).tree)) }
}

unsafe fn shared_dict_state_sentinel(
    state: NonNull<SharedDictState>,
) -> NonNull<ngx_rbtree_node_t> {
    unsafe { NonNull::new_unchecked(ptr::addr_of_mut!((*state.as_ptr()).sentinel)) }
}

unsafe fn shared_dict_state_queue(state: NonNull<SharedDictState>) -> NonNull<ngx_queue_t> {
    unsafe { NonNull::new_unchecked(ptr::addr_of_mut!((*state.as_ptr()).queue)) }
}

unsafe fn shared_dict_entry_key(entry: &SharedDictEntry) -> &[u8] {
    let data =
        unsafe { (ptr::from_ref(entry).cast::<u8>()).add(mem::size_of::<SharedDictEntry>()) };
    unsafe { slice::from_raw_parts(data, entry.key_len) }
}

unsafe fn shared_dict_entry_value(entry: &SharedDictEntry) -> &[u8] {
    let data = unsafe {
        (ptr::from_ref(entry).cast::<u8>())
            .add(mem::size_of::<SharedDictEntry>())
            .add(entry.key_len)
    };
    unsafe { slice::from_raw_parts(data, entry.value_len) }
}

unsafe extern "C" fn shared_dict_rbtree_insert(
    mut current: *mut ngx_rbtree_node_t,
    node: *mut ngx_rbtree_node_t,
    sentinel: *mut ngx_rbtree_node_t,
) {
    loop {
        let link = unsafe {
            match (*node).key.cmp(&(*current).key) {
                Ordering::Less => &mut (*current).left,
                Ordering::Greater => &mut (*current).right,
                Ordering::Equal => {
                    let node = &*node.cast::<SharedDictEntry>();
                    let current_entry = &*current.cast::<SharedDictEntry>();
                    if shared_dict_entry_key(node).cmp(shared_dict_entry_key(current_entry))
                        == Ordering::Less
                    {
                        &mut (*current).left
                    } else {
                        &mut (*current).right
                    }
                }
            }
        };
        if ptr::addr_eq(*link, sentinel) {
            *link = node;
            break;
        }
        current = *link;
    }

    unsafe {
        (*node).parent = current;
        (*node).left = sentinel;
        (*node).right = sentinel;
        ngx_rbt_red(node);
    }
}

fn shared_dict_entry_layout(key_len: usize, value_len: usize) -> Result<Layout, Status> {
    let tail_len = key_len.checked_add(value_len).ok_or(Status::NGX_ERROR)?;
    SlabRegion::flexible_layout::<SharedDictEntry>(tail_len).map_err(|_| Status::NGX_ERROR)
}

fn shared_dict_entry_layout_for(entry: NonNull<SharedDictEntry>) -> Result<Layout, Status> {
    let entry = unsafe { entry.as_ref() };
    shared_dict_entry_layout(entry.key_len, entry.value_len)
}

fn shared_dict_allocate_entry(
    guard: &mut SlabGuard<'_, '_>,
    key: &[u8],
    value: &[u8],
) -> Result<NonNull<SharedDictEntry>, Status> {
    let layout = shared_dict_entry_layout(key.len(), value.len())?;
    let region = guard
        .try_calloc_region(layout, |bytes| {
            let header_len = mem::size_of::<SharedDictEntry>();
            let entry = bytes.as_mut_ptr().cast::<SharedDictEntry>();
            unsafe {
                (*entry).tree.key = shared_dict_hash(key);
                (*entry).key_len = key.len();
                (*entry).value_len = value.len();
            }
            let tail = &mut bytes[header_len..];
            tail[..key.len()].copy_from_slice(key);
            tail[key.len()..].copy_from_slice(value);
            Ok::<_, Status>(())
        })
        .map_err(|_| Status::NGX_ERROR)?;
    let entry = region.as_ptr().cast::<SharedDictEntry>();
    let _ = region.into_raw_parts();
    Ok(entry)
}

fn shared_dict_free_entry(
    guard: &mut SlabGuard<'_, '_>,
    entry: NonNull<SharedDictEntry>,
) -> Result<(), Status> {
    let layout = shared_dict_entry_layout_for(entry)?;
    let region =
        unsafe { guard.region_from_raw(entry.cast(), layout) }.map_err(|_| Status::NGX_ERROR)?;
    unsafe { guard.free_region(region) }.map_err(|_| Status::NGX_ERROR)
}

fn shared_dict_pool(shm_zone: &ngx_shm_zone_t) -> Result<SlabPool<'_>, Status> {
    unsafe { SlabPool::from_shm_zone(shm_zone) }.map_err(|_| Status::NGX_ERROR)
}

fn shared_dict_state(guard: &SlabGuard<'_, '_>) -> Result<NonNull<SharedDictState>, Status> {
    let pool = unsafe { guard.raw_pool() };
    let state = NonNull::new(unsafe { pool.as_ref().data }.cast::<SharedDictState>())
        .ok_or(Status::NGX_ERROR)?;
    unsafe { guard.get(state) }.map_err(|_| Status::NGX_ERROR)?;
    Ok(state)
}

fn shared_dict_entries(state: NonNull<SharedDictState>) -> usize {
    unsafe { (*state.as_ptr()).entries }
}

fn shared_dict_increment_entries(state: NonNull<SharedDictState>) -> Result<(), Status> {
    let entries = shared_dict_entries(state).checked_add(1).ok_or(Status::NGX_ERROR)?;
    unsafe { (*state.as_ptr()).entries = entries };
    Ok(())
}

fn shared_dict_decrement_entries(state: NonNull<SharedDictState>) -> Result<(), Status> {
    let entries = shared_dict_entries(state).checked_sub(1).ok_or(Status::NGX_ERROR)?;
    unsafe { (*state.as_ptr()).entries = entries };
    Ok(())
}

fn shared_dict_validate(
    guard: &mut SlabGuard<'_, '_>,
    state: NonNull<SharedDictState>,
) -> Result<(), Status> {
    {
        let tree = unsafe {
            SlabRbTree::<SharedDictEntry>::from_raw(guard, shared_dict_state_tree(state))
        }
        .map_err(|_| Status::NGX_ERROR)?;
        tree.is_empty().map_err(|_| Status::NGX_ERROR)?;
    }
    {
        let queue = unsafe {
            SlabQueue::<SharedDictEntry>::from_raw(guard, shared_dict_state_queue(state))
        }
        .map_err(|_| Status::NGX_ERROR)?;
        queue.is_empty().map_err(|_| Status::NGX_ERROR)?;
    }
    Ok(())
}

fn shared_dict_init_shared(shm_zone: &mut ngx_shm_zone_t) -> Result<(), Status> {
    let mut pool = shared_dict_pool(shm_zone)?;
    let mut guard = pool.lock();
    let mut native_pool = unsafe { guard.raw_pool() };
    let has_state = !unsafe { native_pool.as_ref().data }.is_null();

    if shm_zone.shm.exists != 0 {
        if !has_state {
            return Err(Status::NGX_ERROR);
        }
        let state = shared_dict_state(&guard)?;
        return shared_dict_validate(&mut guard, state);
    }
    if has_state {
        return Err(Status::NGX_ERROR);
    }

    let region =
        guard.calloc_region(Layout::new::<SharedDictState>()).map_err(|_| Status::NGX_ERROR)?;
    let state = region.as_ptr().cast::<SharedDictState>();
    unsafe { state.as_ptr().write(mem::zeroed()) };

    if unsafe {
        SlabRbTree::<SharedDictEntry>::init(
            &mut guard,
            shared_dict_state_tree(state),
            shared_dict_state_sentinel(state),
            Some(shared_dict_rbtree_insert),
        )
    }
    .is_err()
    {
        unsafe { guard.free_region(region) }.map_err(|_| Status::NGX_ERROR)?;
        return Err(Status::NGX_ERROR);
    }
    if unsafe { SlabQueue::<SharedDictEntry>::init(&mut guard, shared_dict_state_queue(state)) }
        .is_err()
    {
        unsafe { guard.free_region(region) }.map_err(|_| Status::NGX_ERROR)?;
        return Err(Status::NGX_ERROR);
    }

    unsafe { native_pool.as_mut().data = state.as_ptr().cast() };
    let _ = region.into_raw_parts();
    Ok(())
}

fn shared_dict_find(
    guard: &mut SlabGuard<'_, '_>,
    state: NonNull<SharedDictState>,
    key: &[u8],
) -> Result<Option<NonNull<SharedDictEntry>>, Status> {
    let max_steps = shared_dict_entries(state).saturating_add(1);
    let tree =
        unsafe { SlabRbTree::<SharedDictEntry>::from_raw(guard, shared_dict_state_tree(state)) }
            .map_err(|_| Status::NGX_ERROR)?;
    let entry = unsafe {
        tree.find_by(shared_dict_hash(key), max_steps, |entry| {
            key.cmp(shared_dict_entry_key(entry))
        })
    }
    .map_err(|_| Status::NGX_ERROR)?;
    Ok(entry.map(|entry| NonNull::from(entry.entry())))
}

fn shared_dict_insert_tree(
    guard: &mut SlabGuard<'_, '_>,
    state: NonNull<SharedDictState>,
    entry: NonNull<SharedDictEntry>,
) -> Result<(), Status> {
    let mut tree =
        unsafe { SlabRbTree::<SharedDictEntry>::from_raw(guard, shared_dict_state_tree(state)) }
            .map_err(|_| Status::NGX_ERROR)?;
    unsafe { tree.insert(entry) }.map_err(|_| Status::NGX_ERROR)
}

fn shared_dict_remove_tree(
    guard: &mut SlabGuard<'_, '_>,
    state: NonNull<SharedDictState>,
    entry: NonNull<SharedDictEntry>,
) -> Result<(), Status> {
    let mut tree =
        unsafe { SlabRbTree::<SharedDictEntry>::from_raw(guard, shared_dict_state_tree(state)) }
            .map_err(|_| Status::NGX_ERROR)?;
    unsafe { tree.remove(entry) }.map_err(|_| Status::NGX_ERROR)
}

fn shared_dict_insert_queue(
    guard: &mut SlabGuard<'_, '_>,
    state: NonNull<SharedDictState>,
    entry: NonNull<SharedDictEntry>,
) -> Result<(), Status> {
    let mut queue =
        unsafe { SlabQueue::<SharedDictEntry>::from_raw(guard, shared_dict_state_queue(state)) }
            .map_err(|_| Status::NGX_ERROR)?;
    unsafe { queue.push_front(entry) }.map_err(|_| Status::NGX_ERROR)
}

fn shared_dict_remove_queue(
    guard: &mut SlabGuard<'_, '_>,
    state: NonNull<SharedDictState>,
    entry: NonNull<SharedDictEntry>,
) -> Result<(), Status> {
    let mut queue =
        unsafe { SlabQueue::<SharedDictEntry>::from_raw(guard, shared_dict_state_queue(state)) }
            .map_err(|_| Status::NGX_ERROR)?;
    unsafe { queue.remove(entry) }.map_err(|_| Status::NGX_ERROR)
}

fn shared_dict_link_entry(
    guard: &mut SlabGuard<'_, '_>,
    state: NonNull<SharedDictState>,
    entry: NonNull<SharedDictEntry>,
) -> Result<(), Status> {
    shared_dict_insert_tree(guard, state, entry)?;
    if shared_dict_insert_queue(guard, state, entry).is_err() {
        shared_dict_remove_tree(guard, state, entry)?;
        return Err(Status::NGX_ERROR);
    }
    Ok(())
}

fn shared_dict_detach_entry(
    guard: &mut SlabGuard<'_, '_>,
    state: NonNull<SharedDictState>,
    entry: NonNull<SharedDictEntry>,
) -> Result<(), Status> {
    shared_dict_remove_queue(guard, state, entry)?;
    if shared_dict_remove_tree(guard, state, entry).is_err() {
        shared_dict_insert_queue(guard, state, entry)?;
        return Err(Status::NGX_ERROR);
    }
    Ok(())
}

fn shared_dict_touch_entry(
    guard: &mut SlabGuard<'_, '_>,
    state: NonNull<SharedDictState>,
    entry: NonNull<SharedDictEntry>,
) -> Result<(), Status> {
    let mut queue =
        unsafe { SlabQueue::<SharedDictEntry>::from_raw(guard, shared_dict_state_queue(state)) }
            .map_err(|_| Status::NGX_ERROR)?;
    unsafe { queue.move_to_front(entry) }.map_err(|_| Status::NGX_ERROR)
}

fn shared_dict_set_value(
    shm_zone: &ngx_shm_zone_t,
    key: &[u8],
    value: &[u8],
) -> Result<(), Status> {
    let mut pool = shared_dict_pool(shm_zone)?;
    let mut guard = pool.lock();
    let state = shared_dict_state(&guard)?;
    let previous = shared_dict_find(&mut guard, state, key)?;
    let entry = shared_dict_allocate_entry(&mut guard, key, value)?;

    if let Some(previous) = previous {
        shared_dict_detach_entry(&mut guard, state, previous)?;
        if shared_dict_link_entry(&mut guard, state, entry).is_err() {
            shared_dict_link_entry(&mut guard, state, previous)?;
            return Err(Status::NGX_ERROR);
        }
        return shared_dict_free_entry(&mut guard, previous);
    }

    shared_dict_link_entry(&mut guard, state, entry)?;
    shared_dict_increment_entries(state)
}

fn shared_dict_get_value(
    shm_zone: &ngx_shm_zone_t,
    key: &[u8],
    request_pool: *mut ngx_pool_t,
) -> Result<Option<ngx_str_t>, Status> {
    let mut pool = shared_dict_pool(shm_zone)?;
    let mut guard = pool.lock();
    let state = shared_dict_state(&guard)?;
    let Some(entry) = shared_dict_find(&mut guard, state, key)? else {
        return Ok(None);
    };
    let value = unsafe { shared_dict_entry_value(entry.as_ref()) };
    let value = unsafe { ngx_str_t::from_bytes(request_pool, value) }.ok_or(Status::NGX_ERROR)?;
    shared_dict_touch_entry(&mut guard, state, entry)?;
    Ok(Some(value))
}

fn shared_dict_delete_value(shm_zone: &ngx_shm_zone_t, key: &[u8]) -> Result<bool, Status> {
    let mut pool = shared_dict_pool(shm_zone)?;
    let mut guard = pool.lock();
    let state = shared_dict_state(&guard)?;
    let Some(entry) = shared_dict_find(&mut guard, state, key)? else {
        return Ok(false);
    };
    shared_dict_detach_entry(&mut guard, state, entry)?;
    shared_dict_free_entry(&mut guard, entry)?;
    shared_dict_decrement_entries(state)?;
    Ok(true)
}

fn shared_dict_entries_value(
    shm_zone: &ngx_shm_zone_t,
    request_pool: *mut ngx_pool_t,
) -> Result<ngx_str_t, Status> {
    let Some(request_pool) = (unsafe { Pool::from_raw(request_pool) }) else {
        return Err(Status::NGX_ERROR);
    };
    let mut pool = shared_dict_pool(shm_zone)?;
    let mut guard = pool.lock();
    let state = shared_dict_state(&guard)?;
    let entries = shared_dict_entries(state);
    let max_entries = entries.saturating_add(1);
    let queue = unsafe {
        SlabQueue::<SharedDictEntry>::from_raw(&mut guard, shared_dict_state_queue(state))
    }
    .map_err(|_| Status::NGX_ERROR)?;

    let mut len = entries.checked_ilog10().unwrap_or(0) as usize + b"0; ".len();
    for entry in queue.iter(max_entries) {
        let entry = entry.map_err(|_| Status::NGX_ERROR)?;
        let entry = entry.entry();
        let key = unsafe { shared_dict_entry_key(entry) };
        let value = unsafe { shared_dict_entry_value(entry) };
        len = len
            .checked_add(key.len())
            .and_then(|len| len.checked_add(value.len()))
            .and_then(|len| len.checked_add(b" = ; ".len()))
            .ok_or(Status::NGX_ERROR)?;
    }

    let mut output = NgxString::new_in(request_pool);
    output.try_reserve(len).map_err(|_| Status::NGX_ERROR)?;
    write!(output, "{entries}; ").map_err(|_| Status::NGX_ERROR)?;
    for entry in queue.iter(max_entries) {
        let entry = entry.map_err(|_| Status::NGX_ERROR)?;
        let entry = entry.entry();
        let key = unsafe { shared_dict_entry_key(entry) };
        let value = unsafe { shared_dict_entry_value(entry) };
        output.try_append(key).map_err(|_| Status::NGX_ERROR)?;
        output.write_str(" = ").map_err(|_| Status::NGX_ERROR)?;
        output.try_append(value).map_err(|_| Status::NGX_ERROR)?;
        output.write_str("; ").map_err(|_| Status::NGX_ERROR)?;
    }

    let (data, len, _, _) = output.into_raw_parts();
    Ok(ngx_str_t { data, len })
}

fn shared_dict_clear(shm_zone: &ngx_shm_zone_t) -> Result<(), Status> {
    let mut pool = shared_dict_pool(shm_zone)?;
    let mut guard = pool.lock();
    let state = shared_dict_state(&guard)?;

    while shared_dict_entries(state) != 0 {
        let entry = {
            let queue = unsafe {
                SlabQueue::<SharedDictEntry>::from_raw(&mut guard, shared_dict_state_queue(state))
            }
            .map_err(|_| Status::NGX_ERROR)?;
            queue
                .front()
                .map_err(|_| Status::NGX_ERROR)?
                .map(|entry| NonNull::from(entry.entry()))
                .ok_or(Status::NGX_ERROR)?
        };
        shared_dict_detach_entry(&mut guard, state, entry)?;
        shared_dict_free_entry(&mut guard, entry)?;
        shared_dict_decrement_entries(state)?;
    }

    Ok(())
}

extern "C" fn ngx_http_shared_dict_add_zone(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let Some(cf) = (unsafe { cf.as_mut() }) else {
        return NGX_CONF_ERROR;
    };
    let Some(smcf) = (unsafe { conf.cast::<SharedDictMainConfig>().as_mut() }) else {
        return NGX_CONF_ERROR;
    };

    debug_assert!(!cf.args.is_null() && unsafe { (*cf.args).nelts >= 3 });
    let args = unsafe { (*cf.args).as_slice_mut() };

    let mut name: ngx_str_t = args[1];
    let size = unsafe { ngx_parse_size(&raw mut args[2]) };
    if size == -1 {
        return NGX_CONF_ERROR;
    }

    smcf.shm_zone = unsafe {
        ngx_shared_memory_add(
            cf,
            &raw mut name,
            size as usize,
            (&raw mut ngx_http_shared_dict_module).cast(),
        )
    };

    let Some(shm_zone) = (unsafe { smcf.shm_zone.as_mut() }) else {
        return NGX_CONF_ERROR;
    };

    shm_zone.init = Some(ngx_http_shared_dict_zone_init);
    shm_zone.data = ptr::from_mut(smcf).cast();

    NGX_CONF_OK
}

extern "C" fn ngx_http_shared_dict_zone_init(
    shm_zone: *mut ngx_shm_zone_t,
    _data: *mut c_void,
) -> ngx_int_t {
    let Some(shm_zone) = (unsafe { shm_zone.as_mut() }) else {
        return Status::NGX_ERROR.into();
    };

    match shared_dict_init_shared(shm_zone) {
        Err(status) => status.into(),
        Ok(()) => Status::NGX_OK.into(),
    }
}

extern "C" fn ngx_http_shared_dict_add_variable(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    _conf: *mut c_void,
) -> *mut c_char {
    let Some(cf) = (unsafe { cf.as_mut() }) else {
        return NGX_CONF_ERROR;
    };
    let Some(pool) = (unsafe { Pool::from_raw(cf.pool) }) else {
        return NGX_CONF_ERROR;
    };

    let key = pool.calloc_type::<ngx_http_complex_value_t>();
    if key.is_null() {
        return NGX_CONF_ERROR;
    }

    debug_assert!(!cf.args.is_null() && unsafe { (*cf.args).nelts >= 3 });
    let args = unsafe { (*cf.args).as_slice_mut() };

    let mut ccv: ngx_http_compile_complex_value_t = unsafe { mem::zeroed() };
    ccv.cf = cf;
    ccv.value = &raw mut args[1];
    ccv.complex_value = key;

    if unsafe { nginx_sys::ngx_http_compile_complex_value(&raw mut ccv) } != Status::NGX_OK.into() {
        return NGX_CONF_ERROR;
    }

    let Some(name) = variable_name(args[2]) else {
        ngx_conf_log_error!(NGX_LOG_EMERG, cf, "invalid variable name \"{}\"", args[2]);
        return NGX_CONF_ERROR;
    };

    let name = unsafe { NgxStr::from_ngx_str(name) };
    let registration = unsafe {
        HttpConfigurationParser::with_raw(cf, |parser| {
            add_variable_with_setter::<SharedDictVariable, SharedDictVariable>(
                parser,
                name,
                HttpVariableFlags::CHANGEABLE | HttpVariableFlags::NOCACHEABLE,
                key as usize,
            )
        })
    };
    if !matches!(registration, Ok(Ok(()))) {
        return NGX_CONF_ERROR;
    }

    NGX_CONF_OK
}

struct SharedDictVariable;

impl HttpVariableHandler for SharedDictVariable {
    type Output = Status;

    fn get(
        request: &mut RequestRefMut<'_>,
        output: &mut HttpVariableOutput<'_>,
        data: usize,
    ) -> Self::Output {
        let mut key = ngx_str_t::empty();
        if unsafe { ngx_http_complex_value(request.as_ptr(), data as _, &raw mut key) }
            != Status::NGX_OK.into()
        {
            return Status::NGX_ERROR;
        }

        let Ok(Some(smcf)) = request.main_conf::<HttpSharedDictModule>() else {
            return Status::NGX_ERROR;
        };
        let Some(shm_zone) = smcf.shm_zone() else {
            output.set_not_found();
            return Status::NGX_OK;
        };

        let key = unsafe { NgxStr::from_ngx_str(key) };
        let request_pool = match request.pool() {
            Ok(pool) => pool.as_ptr(),
            Err(_) => return Status::NGX_ERROR,
        };
        let value = match shared_dict_get_value(shm_zone, key.as_bytes(), request_pool) {
            Err(status) => return status,
            Ok(None) => {
                output.set_not_found();
                return Status::NGX_OK;
            }
            Ok(Some(value)) => value,
        };

        ngx_log_debug!(
            unsafe { (*(*request.as_ptr()).connection).log },
            "shared dict: get \"{}\" w:{} p:{}",
            key,
            unsafe { nginx_sys::ngx_worker },
            unsafe { nginx_sys::ngx_pid },
        );

        let value = unsafe { NgxStr::from_ngx_str(value) };
        output
            .copy_from_request(request, value.as_bytes())
            .map(|()| Status::NGX_OK)
            .unwrap_or(Status::NGX_ERROR)
    }
}

impl HttpVariableSetter for SharedDictVariable {
    fn set(request: &mut RequestRefMut<'_>, value: HttpVariableValueRef<'_>, data: usize) {
        let mut key = ngx_str_t::empty();
        if unsafe { ngx_http_complex_value(request.as_ptr(), data as _, &raw mut key) }
            != Status::NGX_OK.into()
        {
            return;
        }

        let Ok(Some(smcf)) = request.main_conf::<HttpSharedDictModule>() else {
            return;
        };
        let Some(shm_zone) = smcf.shm_zone() else {
            return;
        };
        let key = unsafe { NgxStr::from_ngx_str(key) };

        if unsafe { (*request.as_ptr()).method } == NGX_HTTP_DELETE as _ {
            if shared_dict_delete_value(shm_zone, key.as_bytes()).is_ok() {
                ngx_log_debug!(
                    unsafe { (*(*request.as_ptr()).connection).log },
                    "shared dict: delete \"{}\" w:{} p:{}",
                    key,
                    unsafe { nginx_sys::ngx_worker },
                    unsafe { nginx_sys::ngx_pid },
                );
            }
            return;
        }

        if shared_dict_set_value(shm_zone, key.as_bytes(), value.bytes().unwrap_or_default())
            .is_ok()
        {
            ngx_log_debug!(
                unsafe { (*(*request.as_ptr()).connection).log },
                "shared dict: set \"{}\" w:{} p:{}",
                key,
                unsafe { nginx_sys::ngx_worker },
                unsafe { nginx_sys::ngx_pid },
            );
        }
    }
}

struct SharedDictEntriesVariable;

impl HttpVariableHandler for SharedDictEntriesVariable {
    type Output = Status;

    fn get(
        request: &mut RequestRefMut<'_>,
        output: &mut HttpVariableOutput<'_>,
        _data: usize,
    ) -> Self::Output {
        let Ok(Some(smcf)) = request.main_conf::<HttpSharedDictModule>() else {
            return Status::NGX_ERROR;
        };

        let Some(shm_zone) = smcf.shm_zone() else {
            output.set_not_found();
            return Status::NGX_OK;
        };
        let request_pool = match request.pool() {
            Ok(pool) => pool.as_ptr(),
            Err(_) => return Status::NGX_ERROR,
        };
        let value = match shared_dict_entries_value(shm_zone, request_pool) {
            Err(status) => return status,
            Ok(value) => value,
        };

        ngx_log_debug!(
            unsafe { (*(*request.as_ptr()).connection).log },
            "shared dict: get all entries"
        );

        let value = unsafe { NgxStr::from_ngx_str(value) };
        output
            .copy_from_request_uncached(request, value.as_bytes())
            .map(|()| Status::NGX_OK)
            .unwrap_or(Status::NGX_ERROR)
    }
}

impl HttpVariableSetter for SharedDictEntriesVariable {
    fn set(request: &mut RequestRefMut<'_>, _value: HttpVariableValueRef<'_>, _data: usize) {
        let Ok(Some(smcf)) = request.main_conf::<HttpSharedDictModule>() else {
            return;
        };
        let Some(shm_zone) = smcf.shm_zone() else {
            return;
        };

        if shared_dict_clear(shm_zone).is_ok() {
            ngx_log_debug!(unsafe { (*(*request.as_ptr()).connection).log }, "shared dict: clear");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variable_name_requires_a_nonempty_dollar_prefixed_name() {
        let name = variable_name(ngx_string!("$value")).unwrap();
        assert_eq!(name.as_bytes(), b"value");
        assert!(variable_name(ngx_string!("")).is_none());
        assert!(variable_name(ngx_string!("$")).is_none());
        assert!(variable_name(ngx_string!("value")).is_none());
    }

    #[test]
    fn default_config_has_no_shared_memory_zone() {
        assert!(SharedDictMainConfig::default().shm_zone().is_none());
    }

    #[test]
    fn rbtree_hash_keeps_colliding_keys_distinct_for_secondary_ordering() {
        assert_eq!(shared_dict_hash(b"Aa"), shared_dict_hash(b"BB"));
        assert_ne!(b"Aa".cmp(b"BB"), Ordering::Equal);
    }

    #[test]
    fn flexible_entry_layout_covers_empty_and_overflowing_tails() {
        let layout = shared_dict_entry_layout(0, 0).unwrap();
        assert_eq!(layout.size(), mem::size_of::<SharedDictEntry>());
        assert_eq!(shared_dict_entry_layout(usize::MAX, 1), Err(Status::NGX_ERROR));
    }
}
