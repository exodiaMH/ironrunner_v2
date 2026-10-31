use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_GUARD, PAGE_NOACCESS, VirtualQuery,
};
use windows::core::{PCSTR, s};

#[derive(Clone, Copy)]
pub enum MHFOInfo {
    LowGrade(Addresses),
    HighGrade(Addresses),
}

#[derive(Clone, Copy)]
pub struct Addresses {
    pub dll: usize,
    pub input_func: usize,
    pub controller_values: usize,
    pub kbm_disable: KBMDisable,
    pub interaction_state: usize,
    player_base: usize,
    player_idx: usize,
    pub menu_state_identifier_1: usize,
    pub menu_state_identifier_2: usize,
    pub menu_idx: usize,
    pub selected_quest_id: usize,
    pub quest_player_count_selection: usize,
    pub quest_accept_menu_idx: usize,
    pub npc_dialogue_finished: usize,
    pub quest_submenu_open: usize,
    pub previous_quest: usize,
    pub camera_coords: usize,
    pub in_quest_state: usize,
    pub rewards_state: usize,
    pub quest_end_timer: usize,
    pub item_sets: usize,
    pub binds: usize,
    pub departure: usize,
    pub red_box: usize,
    pub small_box: usize,
    pub gem_color: usize,
    pub colors: usize,
    pub gem_level: usize,
    settings_base: usize,
    pub start_menu_idx: usize,
    pub accepted_quest: usize,
    pub portable_controls: usize,
    pub item_box: usize,
}

#[derive(Clone, Copy)]
pub struct KBMDisable {
    kb_call_addr: usize,
    mouse_call_addr: usize,
    kb_orig: [u8; 5],
    mouse_orig: [u8; 5],
}

/// SizeOfImage of the game module. The Rain client decrypts client.dll and maps it manually, so
/// it never shows up in the module list and has to be found by walking the address space.
const CLIENT_IMAGE_SIZE: u32 = 0x6489000;

fn find_mapped_client() -> Option<usize> {
    let mut addr = 0usize;
    loop {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let queried =
            unsafe { VirtualQuery(Some(addr as *const _), &mut mbi, size_of_val(&mbi)) };
        if queried == 0 {
            return None;
        }
        let base = mbi.BaseAddress as usize;
        let readable = mbi.State == MEM_COMMIT
            && mbi.Protect.0 != 0
            && mbi.Protect.0 & (PAGE_NOACCESS.0 | PAGE_GUARD.0) == 0;
        if readable && base == mbi.AllocationBase as usize && mbi.RegionSize >= 0x1000 {
            let header = unsafe { std::slice::from_raw_parts(base as *const u8, 0x1000) };
            if header.starts_with(b"MZ") {
                let pe = u32::from_le_bytes(header[0x3C..0x40].try_into().unwrap()) as usize;
                if pe + 0x54 <= header.len() && &header[pe..pe + 4] == b"PE\0\0" {
                    let size = u32::from_le_bytes(header[pe + 0x50..pe + 0x54].try_into().unwrap());
                    if size == CLIENT_IMAGE_SIZE {
                        return Some(base);
                    }
                }
            }
        }
        addr = base.checked_add(mbi.RegionSize)?;
    }
}

impl MHFOInfo {
    pub fn find_main_dll() -> Option<Self> {
        if let Ok(handle) = unsafe { GetModuleHandleA(PCSTR(s!("mhfo.dll").as_ptr())) } {
            Some(Self::LowGrade(Addresses::new_lge(handle.0.addr())))
        } else {
            find_mapped_client().map(|base| Self::LowGrade(Addresses::new_lge(base)))
        }
    }

    pub fn addresses(&self) -> Addresses {
        match self {
            MHFOInfo::LowGrade(addresses) => *addresses,
            MHFOInfo::HighGrade(addresses) => *addresses,
        }
    }
}

impl KBMDisable {
    fn new(kb_call_addr: usize, mouse_call_addr: usize) -> Self {
        let kb_orig = unsafe { (kb_call_addr as *const [u8; 5]).read() };
        let mouse_orig = unsafe { (mouse_call_addr as *const [u8; 5]).read() };
        Self {
            kb_call_addr,
            mouse_call_addr,
            kb_orig,
            mouse_orig,
        }
    }

    pub fn disable(&self) {
        unsafe {
            (self.kb_call_addr as *mut [u8; 5]).write([0x90; 5]);
            (self.mouse_call_addr as *mut [u8; 5]).write([0x90; 5]);
        }
    }

    pub fn restore(&self) {
        unsafe {
            (self.kb_call_addr as *mut [u8; 5]).write(self.kb_orig);
            (self.mouse_call_addr as *mut [u8; 5]).write(self.mouse_orig);
        }
    }
}

impl Addresses {
    fn new_lge(dll: usize) -> Self {
        let kb_apply_call = dll + 0x8DA52F;
        let mouse_apply_call = dll + 0x8DA7AF;
        let kbm_disable = KBMDisable::new(kb_apply_call, mouse_apply_call);
        Self {
            dll,
            input_func: dll + 0x8D9F60,
            controller_values: dll + 0x5CAC00A,
            kbm_disable,
            interaction_state: dll + 0x61EC140,
            player_base: dll + 0x5033B90,
            player_idx: dll + 0x5BCA704,
            menu_state_identifier_1: dll + 0x61F2FE0,
            menu_state_identifier_2: dll + 0x61F2FE4,
            menu_idx: dll + 0x61EC174,
            selected_quest_id: dll + 0x61181A4,
            quest_player_count_selection: dll + 0x629D920,
            quest_accept_menu_idx: dll + 0x61EFB58,
            npc_dialogue_finished: dll + 0x613F247,
            quest_submenu_open: dll + 0x61EC410,
            previous_quest: dll + 0x1B97740,
            camera_coords: dll + 0x1BF21C0,
            in_quest_state: dll + 0x5034728,
            rewards_state: dll + 0x4FD114C,
            quest_end_timer: dll + 0x2868D80,
            item_sets: dll + 0x5B081B8,
            binds: dll + 0x1C19850,
            departure: dll + 0x18FDEA0,
            red_box: dll + 0x28C3AA0,
            small_box: dll + 0x18FDFC0,
            gem_color: dll + 0x5C1A0F4,
            colors: dll + 0x5C1A0D8,
            gem_level: dll + 0x5C1A0F5,
            settings_base: dll + 0x5BC657A,
            start_menu_idx: dll + 0x5BD591A,
            accepted_quest: dll + 0x5A959EC,
            portable_controls: dll + 0x4FB4FBB, // Hopefully correct, iffy to test
            item_box: dll + 0x5C0BD8C,
        }
    }

    fn new_hge(dll_address: usize) -> Self {
        unimplemented!()
    }

    pub fn target(&self) -> Option<usize> {
        unsafe {
            let player_idx = (self.player_idx as *const u8).read();
            let target_ptr =
                ((self.player_base + player_idx as usize * 0x1050 + 0x44C) as *const usize).read();
            if !(target_ptr as *const usize).is_null() {
                Some(target_ptr)
            } else {
                None
            }
        }
    }

    pub fn target_interaction(&self) -> usize {
        let player_idx = unsafe { (self.player_idx as *const u8).read() };
        self.player_base + player_idx as usize * 0x1050 + 0xB20
    }

    pub fn player_coordinates(&self) -> usize {
        let player_idx = unsafe { (self.player_idx as *const u8).read() };
        self.player_base + player_idx as usize * 0x1050 + 0xAC
    }

    pub fn item_pouch(&self) -> usize {
        let player_idx = unsafe { (self.player_idx as *const u8).read() };
        self.player_base + player_idx as usize * 0x1050 + 0xA18
    }

    pub fn current_stage(&self) -> usize {
        let player_idx = unsafe { (self.player_idx as *const u8).read() };
        self.player_base + player_idx as usize * 0x1050 + 0x7F8
    }

    pub fn in_quest_box_state(&self) -> usize {
        self.in_quest_state + 1
    }

    pub fn in_quest_deposit_idx(&self) -> usize {
        self.in_quest_state + 0xCE
    }

    pub fn rewards_idx(&self) -> usize {
        self.rewards_state + 1
    }

    pub fn rewards_timer(&self) -> usize {
        self.rewards_state + 8
    }

    pub fn settings_idx(&self) -> usize {
        self.settings_base + 0x59
    }

    pub fn settings_submenu_idx(&self) -> usize {
        self.settings_base
    }

    pub fn settings_submenu_page(&self) -> usize {
        self.settings_base + 0x57
    }

    pub fn settings_lobby_movement(&self) -> usize {
        self.settings_base + 0xBC
    }

    pub fn settings_player_interaction(&self) -> usize {
        self.settings_base + 0xBD
    }

    pub fn hunter_quest_idx(&self) -> Option<usize> {
        let ids_len = unsafe { ((self.menu_idx + 0xC) as *const u8).read() };
        let ptr = unsafe { ((self.menu_idx + 0x34) as *const usize).read() } as *const u8;
        if !ptr.is_null() {
            let menu_ids = unsafe { std::slice::from_raw_parts(ptr, ids_len as usize) };
            return menu_ids.iter().position(|id| *id == 0xCD);
        }
        None
    }

    pub fn favorite_idx(&self) -> Option<usize> {
        let ids_len = unsafe { ((self.menu_idx + 0xC) as *const u8).read() };
        let ptr = unsafe { ((self.menu_idx + 0x34) as *const usize).read() } as *const u8;
        if !ptr.is_null() {
            let menu_ids = unsafe { std::slice::from_raw_parts(ptr, ids_len as usize) };
            return menu_ids.iter().position(|id| *id == 0x35);
        }
        None
    }

    pub fn sub_menu_idx(&self) -> usize {
        self.menu_idx + 0x2A0
    }

    pub fn one_star_idx(&self) -> Option<usize> {
        let ids_len = unsafe { ((self.sub_menu_idx() + 0xC) as *const u8).read() };
        let ptr = unsafe { ((self.sub_menu_idx() + 0x34) as *const usize).read() } as *const u8;
        if !ptr.is_null() {
            let menu_ids = unsafe { std::slice::from_raw_parts(ptr, ids_len as usize) };
            return menu_ids.iter().position(|id| *id == 0xCE);
        }
        None
    }
}
