void __fastcall FUN_100059d0(int param_1)

{
  int *piVar1;
  undefined2 *puVar2;
  
  if ((*(int *)(param_1 + 8) != 0) && (*(code **)(param_1 + 0x10) != (code *)0x0)) {
    piVar1 = (int *)(param_1 + 0x18);
    if (7 < *(uint *)(param_1 + 0x2c)) {
      piVar1 = (int *)*piVar1;
    }
    (**(code **)(param_1 + 0x10))(piVar1,*(int *)(param_1 + 8));
  }
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  if (*(HMODULE *)(param_1 + 4) != (HMODULE)0x0) {
    FreeLibrary(*(HMODULE *)(param_1 + 4));
    *(undefined4 *)(param_1 + 4) = 0;
  }
  *(undefined4 *)(param_1 + 0x14) = 0;
  puVar2 = (undefined2 *)(param_1 + 0x18);
  *(undefined4 *)(param_1 + 0x10) = 0;
  if (7 < *(uint *)(param_1 + 0x2c)) {
    puVar2 = *(undefined2 **)(param_1 + 0x18);
  }
  *(undefined4 *)(param_1 + 0x28) = 0;
  *puVar2 = 0;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10005a40 @ 10005a40