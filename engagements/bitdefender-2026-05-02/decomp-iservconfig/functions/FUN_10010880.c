void __fastcall FUN_10010880(int *param_1)

{
  int iVar1;
  int iVar2;
  void *pvVar3;
  uint uVar4;
  undefined4 *puVar5;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 uStack_8;
  
  uStack_8 = 0xffffffff;
  puStack_c = &LAB_1004ead0;
  local_10 = ExceptionList;
  uVar4 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  *param_1 = (int)std::basic_filebuf<char,struct_std::char_traits<char>_>::vftable;
  if ((param_1[0x13] != 0) && (*(int **)param_1[3] == param_1 + 0xf)) {
    iVar1 = param_1[0x15];
    iVar2 = param_1[0x14];
    *(int *)param_1[3] = iVar2;
    *(int *)param_1[7] = iVar2;
    *(int *)param_1[0xb] = iVar1 - iVar2;
  }
  if ((char)param_1[0x12] != '\0') {
    if (param_1[0x13] != 0) {
      if (*(int **)param_1[3] == param_1 + 0xf) {
        iVar1 = param_1[0x15];
        iVar2 = param_1[0x14];
        *(int *)param_1[3] = iVar2;
        *(int *)param_1[7] = iVar2;
        *(int *)param_1[0xb] = iVar1 - iVar2;
      }
      FUN_100119a0(param_1);
      _fclose((FILE *)param_1[0x13]);
    }
    param_1[3] = (int)(param_1 + 1);
    *(undefined1 *)(param_1 + 0x12) = 0;
    *(undefined1 *)((int)param_1 + 0x3d) = 0;
    param_1[4] = (int)(param_1 + 2);
    param_1[7] = (int)(param_1 + 5);
    param_1[8] = (int)(param_1 + 6);
    param_1[0xb] = (int)(param_1 + 9);
    param_1[0xc] = (int)(param_1 + 10);
    param_1[2] = 0;
    param_1[6] = 0;
    iVar2 = DAT_1006b634;
    param_1[10] = 0;
    iVar1 = DAT_1006b630;
    param_1[1] = 0;
    param_1[5] = 0;
    param_1[9] = 0;
    param_1[0x13] = 0;
    param_1[0x10] = iVar1;
    param_1[0x11] = iVar2;
    param_1[0xe] = 0;
  }
  pvVar3 = (void *)param_1[0xd];
  *param_1 = (int)std::basic_streambuf<char,struct_std::char_traits<char>_>::vftable;
  if (pvVar3 != (void *)0x0) {
    if (*(int **)((int)pvVar3 + 4) != (int *)0x0) {
      puVar5 = (undefined4 *)(**(code **)(**(int **)((int)pvVar3 + 4) + 8))(uVar4);
      if (puVar5 != (undefined4 *)0x0) {
        (**(code **)*puVar5)(1);
      }
    }
    FUN_1002e346(pvVar3);
  }
  ExceptionList = local_10;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100109e0 @ 100109e0