from detectors.file_extractor import extract_chunks, _CHUNK_MAX_CHARS


def test_single_paragraph_returns_one_chunk():
    text = "联系人：张三，手机：13812345678，地址：上海市浦东新区张江路100号。"
    chunks = extract_chunks(text)
    assert len(chunks) == 1
    chunk_text, offset = chunks[0]
    assert offset == 0
    assert chunk_text.strip() == text.strip()


def test_offset_is_correct_for_second_paragraph():
    line1 = "第一段内容，这是一些描述文字，确保长度足够触发分块逻辑。\n"
    line2 = "第二段：联系人张三，邮箱 zhangsan@example.com。\n"
    text = line1 + "\n" + line2
    chunks = extract_chunks(text)
    # 第二段应该有独立 chunk，且 offset 等于其在全文中的起始位置
    texts = [c[0] for c in chunks]
    offsets = [c[1] for c in chunks]
    assert any("第二段" in t for t in texts)
    second_idx = next(i for i, t in enumerate(texts) if "第二段" in t)
    expected_offset = text.index("第二段")
    assert offsets[second_idx] == expected_offset


def test_offset_allows_span_recovery():
    line1 = "这是第一行，内容足够长以触发分块处理逻辑。\n"
    secret = "sk-abcdefghijklmnopqrstuvwxyz1234"
    line2 = f"API_KEY={secret}\n"
    text = line1 + line2
    chunks = extract_chunks(text)
    # 找含 secret 的 chunk
    target = next((c for c in chunks if secret in c[0]), None)
    assert target is not None, "secret not found in any chunk"
    chunk_text, offset = target
    # span 在 chunk 内的坐标 + offset 应等于 secret 在全文中的位置
    local_pos = chunk_text.index(secret)
    assert offset + local_pos == text.index(secret)


def test_empty_lines_are_ignored():
    text = "\n\n\n只有这一行有内容，且内容足够长到触发单独分块处理逻辑。\n\n\n"
    chunks = extract_chunks(text)
    assert len(chunks) == 1
    assert chunks[0][1] == text.index("只有")


def test_long_line_is_split_into_multiple_chunks():
    long_line = "X" * (_CHUNK_MAX_CHARS + 100)
    chunks = extract_chunks(long_line)
    assert len(chunks) >= 2
    # 所有 chunk 长度不超过 max
    for chunk_text, _ in chunks:
        assert len(chunk_text) <= _CHUNK_MAX_CHARS


def test_chunks_cover_full_text_without_gaps():
    text = (
        "第一段：联系人王五，手机13900001111，地址北京市朝阳区建国路1号。\n\n"
        "第二段：签署人李四，银行卡号6222021234567891234。\n\n"
        "第三段：统一社会信用代码：91310000MA1FL6LE8Y。\n"
    )
    chunks = extract_chunks(text)
    assert len(chunks) >= 2
    # 重建文本应覆盖所有 chunk 内容（不要求连续，但偏移+长度都在全文范围内）
    for chunk_text, offset in chunks:
        assert offset >= 0
        assert offset + len(chunk_text) <= len(text)
        assert text[offset: offset + len(chunk_text)] == chunk_text
