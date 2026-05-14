void FUN_140013fd0(longlong *param_1,longlong param_2)

{
  longlong lVar1;
  code *pcVar2;
  undefined8 *puVar3;
  _Cvtvec *p_Var4;
  undefined1 *puVar5;
  undefined8 uVar6;
  char *pcVar7;
  undefined1 auStackY_178 [32];
  _Lockit local_148 [8];
  LPVOID local_140;
  undefined1 local_138;
  LPVOID local_130;
  undefined1 local_128;
  LPVOID local_120;
  undefined2 local_118;
  LPVOID local_110;
  undefined2 local_108;
  LPVOID local_100;
  undefined1 local_f8;
  LPVOID local_f0;
  undefined1 local_e8;
  _Cvtvec local_e0;
  _Cvtvec local_b0;
  char local_80 [8];
  char local_78 [8];
  wchar_t local_70 [2];
  uint local_6c;
  undefined8 *local_68;
  undefined8 *local_60;
  _Cvtvec local_58;
  ulonglong local_28;
  
  local_28 = DAT_14007a060 ^ (ulonglong)auStackY_178;
  local_6c = 0;
  if ((param_1 != (longlong *)0x0) && (*param_1 == 0)) {
    puVar3 = (undefined8 *)operator_new(0x30);
    *puVar3 = 0;
    puVar3[1] = 0;
    puVar3[2] = 0;
    puVar3[3] = 0;
    puVar3[4] = 0;
    puVar3[5] = 0;
    lVar1 = *(longlong *)(param_2 + 8);
    if (lVar1 == 0) {
      pcVar7 = "";
    }
    else {
      pcVar7 = *(char **)(lVar1 + 0x28);
      if (pcVar7 == (char *)0x0) {
        pcVar7 = (char *)(lVar1 + 0x30);
      }
    }
    local_60 = puVar3;
    std::_Lockit::_Lockit(local_148,0);
    local_140 = (LPVOID)0x0;
    local_138 = 0;
    local_130 = (LPVOID)0x0;
    local_128 = 0;
    local_120 = (LPVOID)0x0;
    local_118 = 0;
    local_110 = (LPVOID)0x0;
    local_108 = 0;
    local_100 = (LPVOID)0x0;
    local_f8 = 0;
    local_f0 = (LPVOID)0x0;
    local_e8 = 0;
    if (pcVar7 != (char *)0x0) {
      std::_Locinfo::_Locinfo_ctor((_Locinfo *)local_148,pcVar7);
      local_6c = 1;
      *(undefined4 *)(puVar3 + 1) = 0;
      *puVar3 = std::numpunct<wchar_t>::vftable;
      FUN_140035e08();
      p_Var4 = _Getcvt(&local_e0);
      local_58._Page = p_Var4->_Page;
      local_58._Mbcurmax = p_Var4->_Mbcurmax;
      local_58._Isclocale = p_Var4->_Isclocale;
      local_58._Isleadbyte[0] = p_Var4->_Isleadbyte[0];
      local_58._Isleadbyte[1] = p_Var4->_Isleadbyte[1];
      local_58._Isleadbyte[2] = p_Var4->_Isleadbyte[2];
      local_58._Isleadbyte[3] = p_Var4->_Isleadbyte[3];
      local_58._Isleadbyte._4_8_ = *(undefined8 *)(p_Var4->_Isleadbyte + 4);
      local_58._Isleadbyte._12_8_ = *(undefined8 *)(p_Var4->_Isleadbyte + 0xc);
      local_58._Isleadbyte._20_8_ = *(undefined8 *)(p_Var4->_Isleadbyte + 0x14);
      local_58._Isleadbyte._28_4_ = *(undefined4 *)(p_Var4->_Isleadbyte + 0x1c);
      puVar3[2] = 0;
      puVar3[4] = 0;
      puVar3[5] = 0;
      local_68 = puVar3;
      _Getcvt(&local_b0);
      puVar5 = (undefined1 *)_calloc_base(1,1);
      if (puVar5 != (undefined1 *)0x0) {
        *puVar5 = 0;
        puVar3[2] = puVar5;
        uVar6 = FUN_1400024c0("false",0,&local_58);
        puVar3[4] = uVar6;
        uVar6 = FUN_1400024c0("true",0,&local_58);
        puVar3[5] = uVar6;
        local_80[0] = '.';
        local_70[0] = L'\0';
        local_68 = (undefined8 *)0x0;
        _Mbrtowc(local_70,local_80,1,(mbstate_t *)&local_68,&local_58);
        *(wchar_t *)(puVar3 + 3) = local_70[0];
        local_78[0] = ',';
        local_6c = local_6c & 0xffff0000;
        local_60 = (undefined8 *)0x0;
        _Mbrtowc((wchar_t *)&local_6c,local_78,1,(mbstate_t *)&local_60,&local_58);
        *(wchar_t *)((longlong)puVar3 + 0x1a) = (wchar_t)local_6c;
        *param_1 = (longlong)puVar3;
        std::_Locinfo::_Locinfo_dtor((_Locinfo *)local_148);
        if (local_f0 != (LPVOID)0x0) {
          FUN_140035ac0(local_f0);
        }
        local_f0 = (LPVOID)0x0;
        if (local_100 != (LPVOID)0x0) {
          FUN_140035ac0(local_100);
        }
        local_100 = (LPVOID)0x0;
        if (local_110 != (LPVOID)0x0) {
          FUN_140035ac0(local_110);
        }
        local_110 = (LPVOID)0x0;
        if (local_120 != (LPVOID)0x0) {
          FUN_140035ac0(local_120);
        }
        local_120 = (LPVOID)0x0;
        if (local_130 != (LPVOID)0x0) {
          FUN_140035ac0(local_130);
        }
        local_130 = (LPVOID)0x0;
        if (local_140 != (LPVOID)0x0) {
          FUN_140035ac0(local_140);
        }
        local_140 = (LPVOID)0x0;
        std::_Lockit::~_Lockit(local_148);
        goto LAB_14001424e;
      }
      FUN_14002d6b4();
    }
    FUN_14002d73c(0x14006a968);
    pcVar2 = (code *)swi(3);
    (*pcVar2)();
    return;
  }
LAB_14001424e:
  FUN_14002f160(local_28 ^ (ulonglong)auStackY_178);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140014290 @ 140014290