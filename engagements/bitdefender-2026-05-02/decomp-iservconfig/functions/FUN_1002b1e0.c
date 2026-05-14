void __fastcall FUN_1002b1e0(int *param_1)

{
  if ((*(int *)(param_1[1] + 4) == DAT_10069aac) && (*param_1 == 0)) {
                    /* WARNING: Could not recover jumptable at 0x1002b1f3. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    CoUninitialize();
    return;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1002b200 @ 1002b200