void FUN_140019bf0(longlong param_1)

{
  if (*(longlong *)(param_1 + 8) != 0) {
                    /* WARNING: Could not recover jumptable at 0x000140019bf9. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    UnregisterPowerSettingNotification();
    return;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140019c10 @ 140019c10