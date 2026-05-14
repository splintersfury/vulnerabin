undefined8 FUN_1400196b0(longlong *param_1,longlong param_2)

{
  longlong lVar1;
  code *pcVar2;
  undefined8 *puVar3;
  UINT *pUVar4;
  undefined8 uVar5;
  char *pcVar6;
  _Lockit local_a8 [8];
  LPVOID local_a0;
  undefined1 local_98;
  LPVOID local_90;
  undefined1 local_88;
  LPVOID local_80;
  undefined2 local_78;
  LPVOID local_70;
  undefined2 local_68;
  LPVOID local_60;
  undefined1 local_58;
  LPVOID local_50;
  undefined1 local_48;
  UINT local_40 [10];
  
  if ((param_1 != (longlong *)0x0) && (*param_1 == 0)) {
    puVar3 = (undefined8 *)operator_new(0x30);
    lVar1 = *(longlong *)(param_2 + 8);
    if (lVar1 == 0) {
      pcVar6 = "";
    }
    else {
      pcVar6 = *(char **)(lVar1 + 0x28);
      if (pcVar6 == (char *)0x0) {
        pcVar6 = (char *)(lVar1 + 0x30);
      }
    }
    std::_Lockit::_Lockit(local_a8,0);
    local_a0 = (LPVOID)0x0;
    local_98 = 0;
    local_90 = (LPVOID)0x0;
    local_88 = 0;
    local_80 = (LPVOID)0x0;
    local_78 = 0;
    local_70 = (LPVOID)0x0;
    local_68 = 0;
    local_60 = (LPVOID)0x0;
    local_58 = 0;
    local_50 = (LPVOID)0x0;
    local_48 = 0;
    if (pcVar6 == (char *)0x0) {
      FUN_14002d73c(0x14006a968);
      pcVar2 = (code *)swi(3);
      uVar5 = (*pcVar2)();
      return uVar5;
    }
    std::_Locinfo::_Locinfo_ctor((_Locinfo *)local_a8,pcVar6);
    *(undefined4 *)(puVar3 + 1) = 0;
    *puVar3 = std::ctype<char>::vftable;
    pUVar4 = FUN_14002dc94(local_40);
    uVar5 = *(undefined8 *)(pUVar4 + 2);
    puVar3[2] = *(undefined8 *)pUVar4;
    puVar3[3] = uVar5;
    uVar5 = *(undefined8 *)(pUVar4 + 6);
    puVar3[4] = *(undefined8 *)(pUVar4 + 4);
    puVar3[5] = uVar5;
    *param_1 = (longlong)puVar3;
    std::_Locinfo::_Locinfo_dtor((_Locinfo *)local_a8);
    if (local_50 != (LPVOID)0x0) {
      FUN_140035ac0(local_50);
    }
    local_50 = (LPVOID)0x0;
    if (local_60 != (LPVOID)0x0) {
      FUN_140035ac0(local_60);
    }
    local_60 = (LPVOID)0x0;
    if (local_70 != (LPVOID)0x0) {
      FUN_140035ac0(local_70);
    }
    local_70 = (LPVOID)0x0;
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
    std::_Lockit::~_Lockit(local_a8);
  }
  return 2;
}


// FUNCTION_END

// FUNCTION_START: do_tolower @ 140019840

/* Library Function - Single Match
    protected: virtual char __cdecl std::ctype<char>::do_tolower(char)const __ptr64
   
   Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release */

char __thiscall std::ctype<char>::do_tolower(ctype<char> *this,char param_1)

{
  int iVar1;
  
  iVar1 = _Tolower((uint)(byte)param_1,(_Ctypevec *)(this + 0x10));
  return (char)iVar1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140019850 @ 140019850