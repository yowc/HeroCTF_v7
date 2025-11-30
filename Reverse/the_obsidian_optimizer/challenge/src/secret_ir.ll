target triple = "x86_64-pc-linux-gnu"

@flag_str = global [16 x i8] c"Hero{FAKE_FLAG}\00", align 8
@g_random_value = global i64 323232, align 8

@g_table_size = global i64 3, align 8
@jump_table = internal global [4 x ptr] [ptr null, ptr null, ptr null, ptr @get_flag], align 8

declare i32 @puts(i8*)

define i64* @secrets_stage0_factory(i64 %a, i64 %b, i64 %c, i64 %d) {
entry:
  %cmp_1 = icmp eq i64 %a, 1
  br i1 %cmp_1, label %next_2, label %bad

next_2:
  %cmp_2 = icmp eq i64 %b, 2
  br i1 %cmp_2, label %next_3, label %bad

next_3:
  %cmp_3 = icmp eq i64 %c, 3
  br i1 %cmp_3, label %next_4, label %bad

next_4:
  %cmp_4 = icmp eq i64 %d, 4
  br i1 %cmp_4, label %ok, label %bad

ok:
  %p = bitcast ptr @secrets_stage1_factory to i64*
  ret i64* %p

bad:
  ret ptr null
}

define i64* @secrets_stage1_factory(i64 %a) {
entry:
  %cmp = icmp eq i64 %a, -1
  br i1 %cmp, label %ok, label %bad

ok:
  %p = bitcast ptr @secrets_stage2_factory to i64*
  ret i64* %p

bad:
  ret ptr null  
}

define i64* @secrets_stage2_factory(i64 %magic) {
entry:
  %cmp = icmp eq i64 %magic, 8571976399
  br i1 %cmp, label %ok, label %bad

ok:
  %p = bitcast ptr @secrets_read64_at to i64*
  ret i64* %p

  bad:
  ret ptr null  
}

define i64 @secrets_read64_at(i64 %idx) {
entry:
  %cmp = icmp ult i64 %idx, 24
  br i1 %cmp, label %ok, label %bad

ok:
  %is0 = icmp eq i64 %idx, 0
  br i1 %is0, label %r0, label %next_0

r0:
  %v0 = load i64, ptr @g_random_value
  ret i64 %v0

next_0:
  %is8 = icmp eq i64 %idx, 8
  br i1 %is8, label %size, label %next_1

size:
  %table_size = load i64, ptr @g_table_size
  ret i64 %table_size

next_1:
  %is16 = icmp eq i64 %idx, 16
  br i1 %is16, label %jt, label %bad

jt:
  %jtptr = ptrtoint ptr @jump_table to i64
  ret i64 %jtptr

bad:
  ret i64 0
}

define void @get_flag(i64 %val) {
entry:
  %v = load i64, ptr @g_random_value
  %cmp = icmp eq i64 %val, %v
  br i1 %cmp, label %show, label %end

show:
  %ptr = getelementptr inbounds [25 x i8], ptr @flag_str, i64 0, i64 0
  call i32 @puts(ptr %ptr)
  br label %end

end:
  ret void
}

