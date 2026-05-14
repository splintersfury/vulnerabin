undefined * FUN_140008300(void)

{
                    /* WARNING: Load size is inaccurate */
  if (*(int *)(*ThreadLocalStoragePointer + 4) < DAT_14007d558) {
    _Init_thread_header(&DAT_14007d558);
    if (DAT_14007d558 == -1) {
      _DAT_14007d570 = 0;
      _DAT_14007d560 = 0;
      uRam000000014007d568 = 0;
      atexit(FUN_14005a390);
      _Init_thread_footer(&DAT_14007d558);
    }
  }
  return &DAT_14007d560;
}


// FUNCTION_END

// FUNCTION_START: FUN_140008370 @ 140008370