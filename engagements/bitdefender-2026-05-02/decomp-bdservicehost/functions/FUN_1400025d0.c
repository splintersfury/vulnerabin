undefined8 FUN_1400025d0(longlong *param_1,longlong param_2)

{
  longlong lVar1;
  code *pcVar2;
  undefined8 *puVar3;
  UINT *pUVar4;
  _Cvtvec *p_Var5;
  undefined8 uVar6;
  char *pcVar7;
  _Lockit local_d8 [8];
  LPVOID local_d0;
  undefined1 local_c8;
  LPVOID local_c0;
  undefined1 local_b8;
  LPVOID local_b0;
  undefined2 local_a8;
  LPVOID local_a0;
  undefined2 local_98;
  LPVOID local_90;
  undefined1 local_88;
  LPVOID local_80;
  undefined1 local_78;
  UINT local_70 [8];
  _Cvtvec local_50;
  
  if ((param_1 != (longlong *)0x0) && (*param_1 == 0)) {
    puVar3 = (undefined8 *)operator_new(0x60);
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
    std::_Lockit::_Lockit(local_d8,0);
    local_d0 = (LPVOID)0x0;
    local_c8 = 0;
    local_c0 = (LPVOID)0x0;
    local_b8 = 0;
    local_b0 = (LPVOID)0x0;
    local_a8 = 0;
    local_a0 = (LPVOID)0x0;
    local_98 = 0;
    local_90 = (LPVOID)0x0;
    local_88 = 0;
    local_80 = (LPVOID)0x0;
    local_78 = 0;
    if (pcVar7 == (char *)0x0) {
      FUN_14002d73c(0x14006a968);
      pcVar2 = (code *)swi(3);
      uVar6 = (*pcVar2)();
      return uVar6;
    }
    std::_Locinfo::_Locinfo_ctor((_Locinfo *)local_d8,pcVar7);
    *(undefined4 *)(puVar3 + 1) = 0;
    *puVar3 = std::ctype<wchar_t>::vftable;
    pUVar4 = FUN_14002dc94(local_70);
    uVar6 = *(undefined8 *)(pUVar4 + 2);
    puVar3[2] = *(undefined8 *)pUVar4;
    puVar3[3] = uVar6;
    uVar6 = *(undefined8 *)(pUVar4 + 6);
    puVar3[4] = *(undefined8 *)(pUVar4 + 4);
    puVar3[5] = uVar6;
    p_Var5 = _Getcvt(&local_50);
    uVar6 = *(undefined8 *)&p_Var5->_Isclocale;
    puVar3[6] = *(undefined8 *)p_Var5;
    puVar3[7] = uVar6;
    uVar6 = *(undefined8 *)(p_Var5->_Isleadbyte + 0xc);
    puVar3[8] = *(undefined8 *)(p_Var5->_Isleadbyte + 4);
    puVar3[9] = uVar6;
    puVar3[10] = *(undefined8 *)(p_Var5->_Isleadbyte + 0x14);
    *(undefined4 *)(puVar3 + 0xb) = *(undefined4 *)(p_Var5->_Isleadbyte + 0x1c);
    *param_1 = (longlong)puVar3;
    std::_Locinfo::_Locinfo_dtor((_Locinfo *)local_d8);
    if (local_80 != (LPVOID)0x0) {
      FUN_140035ac0(local_80);
    }
    local_80 = (LPVOID)0x0;
    if (local_90 != (LPVOID)0x0) {
      FUN_140035ac0(local_90);
    }
    local_90 = (LPVOID)0x0;
    if (local_a0 != (LPVOID)0x0) {
      FUN_140035ac0(local_a0);
    }
    local_a0 = (LPVOID)0x0;
    if (local_b0 != (LPVOID)0x0) {
      FUN_140035ac0(local_b0);
    }
    local_b0 = (LPVOID)0x0;
    if (local_c0 != (LPVOID)0x0) {
      FUN_140035ac0(local_c0);
    }
    local_c0 = (LPVOID)0x0;
    if (local_d0 != (LPVOID)0x0) {
      FUN_140035ac0(local_d0);
    }
    local_d0 = (LPVOID)0x0;
    std::_Lockit::~_Lockit(local_d8);
  }
  return 2;
}


// FUNCTION_END

// FUNCTION_START: do_is @ 140002790

/* Library Function - Multiple Matches With Same Base Name
    protected: virtual bool __cdecl std::ctype<unsigned short>::do_is(short,unsigned short)const
   __ptr64
    protected: virtual bool __cdecl std::ctype<wchar_t>::do_is(short,wchar_t)const __ptr64
   
   Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release */