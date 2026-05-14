void FUN_1400023b0(_Locinfo *param_1)

{
  std::_Locinfo::_Locinfo_dtor(param_1);
  if (*(LPVOID *)(param_1 + 0x58) != (LPVOID)0x0) {
    FUN_140035ac0(*(LPVOID *)(param_1 + 0x58));
  }
  *(undefined8 *)(param_1 + 0x58) = 0;
  if (*(LPVOID *)(param_1 + 0x48) != (LPVOID)0x0) {
    FUN_140035ac0(*(LPVOID *)(param_1 + 0x48));
  }
  *(undefined8 *)(param_1 + 0x48) = 0;
  if (*(LPVOID *)(param_1 + 0x38) != (LPVOID)0x0) {
    FUN_140035ac0(*(LPVOID *)(param_1 + 0x38));
  }
  *(undefined8 *)(param_1 + 0x38) = 0;
  if (*(LPVOID *)(param_1 + 0x28) != (LPVOID)0x0) {
    FUN_140035ac0(*(LPVOID *)(param_1 + 0x28));
  }
  *(undefined8 *)(param_1 + 0x28) = 0;
  if (*(LPVOID *)(param_1 + 0x18) != (LPVOID)0x0) {
    FUN_140035ac0(*(LPVOID *)(param_1 + 0x18));
  }
  *(undefined8 *)(param_1 + 0x18) = 0;
  if (*(LPVOID *)(param_1 + 8) != (LPVOID)0x0) {
    FUN_140035ac0(*(LPVOID *)(param_1 + 8));
  }
  *(undefined8 *)(param_1 + 8) = 0;
  std::_Lockit::~_Lockit((_Lockit *)param_1);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140002450 @ 140002450