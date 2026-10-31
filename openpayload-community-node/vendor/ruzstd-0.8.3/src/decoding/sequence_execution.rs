use super::scratch::DecoderScratch;
use crate::decoding::errors::ExecuteSequencesError;

/// Take the provided decoder and execute the sequences stored within
pub fn execute_sequences(
    scratch: &mut DecoderScratch,
    max_block_decoded_len: usize,
) -> Result<(), ExecuteSequencesError> {
    let mut literals_copy_counter = 0;
    let old_buffer_size = scratch.buffer.len();
    let mut seq_sum: usize = 0;

    for idx in 0..scratch.sequences.len() {
        let seq = scratch.sequences[idx];
        let next_size = seq_sum.saturating_add(seq.ll as usize).saturating_add(seq.ml as usize);
        if next_size > max_block_decoded_len {
            return Err(ExecuteSequencesError::TooManyBytesGenerated {
                max: max_block_decoded_len,
                decoded: next_size,
            });
        }
        seq_sum = next_size;

        if seq.ll > 0 {
            let high = literals_copy_counter + seq.ll as usize;
            if high > scratch.literals_buffer.len() {
                return Err(ExecuteSequencesError::NotEnoughBytesForSequence {
                    wanted: high,
                    have: scratch.literals_buffer.len(),
                });
            }
            let literals = &scratch.literals_buffer[literals_copy_counter..high];
            literals_copy_counter += seq.ll as usize;

            scratch.buffer.push(literals);
        }

        let actual_offset = do_offset_history(seq.of, seq.ll, &mut scratch.offset_hist);
        if actual_offset == 0 {
            return Err(ExecuteSequencesError::ZeroOffset);
        }
        if seq.ml > 0 {
            scratch
                .buffer
                .repeat(actual_offset as usize, seq.ml as usize)?;
        }


    }
    if literals_copy_counter < scratch.literals_buffer.len() {
        let rest_literals = &scratch.literals_buffer[literals_copy_counter..];
        seq_sum = seq_sum.saturating_add(rest_literals.len());
        if seq_sum > max_block_decoded_len {
            return Err(ExecuteSequencesError::TooManyBytesGenerated {
                max: max_block_decoded_len,
                decoded: seq_sum,
            });
        }
        scratch.buffer.push(rest_literals);
    }

    let diff = scratch.buffer.len() - old_buffer_size;
    assert!(
        seq_sum == diff,
        "Seq_sum: {} is different from the difference in buffersize: {}",
        seq_sum,
        diff
    );
    Ok(())
}

/// Update the most recently used offsets to reflect the provided offset value, and return the
/// "actual" offset needed because offsets are not stored in a raw way, some transformations are needed
/// before you get a functional number.
fn do_offset_history(offset_value: u32, lit_len: u32, scratch: &mut [u32; 3]) -> u32 {
    let actual_offset = if lit_len > 0 {
        match offset_value {
            1..=3 => scratch[offset_value as usize - 1],
            _ => {
                //new offset
                offset_value - 3
            }
        }
    } else {
        match offset_value {
            1..=2 => scratch[offset_value as usize],
            3 => scratch[0] - 1,
            _ => {
                //new offset
                offset_value - 3
            }
        }
    };

    //update history
    if lit_len > 0 {
        match offset_value {
            1 => {
                //nothing
            }
            2 => {
                scratch[1] = scratch[0];
                scratch[0] = actual_offset;
            }
            _ => {
                scratch[2] = scratch[1];
                scratch[1] = scratch[0];
                scratch[0] = actual_offset;
            }
        }
    } else {
        match offset_value {
            1 => {
                scratch[1] = scratch[0];
                scratch[0] = actual_offset;
            }
            2 => {
                scratch[2] = scratch[1];
                scratch[1] = scratch[0];
                scratch[0] = actual_offset;
            }
            _ => {
                scratch[2] = scratch[1];
                scratch[1] = scratch[0];
                scratch[0] = actual_offset;
            }
        }
    }

    actual_offset
}

#[cfg(test)]
mod openpayload_security_tests {
    use super::*;
    use crate::blocks::sequence_section::Sequence;

    #[test]
    fn rejects_oversized_match_before_buffer_growth() {
        let mut scratch = DecoderScratch::new(1024);
        scratch.literals_buffer.push(b'x');
        scratch.sequences.push(Sequence { ll: 1, ml: u32::MAX, of: 1 });
        assert!(matches!(execute_sequences(&mut scratch, 1024), Err(ExecuteSequencesError::TooManyBytesGenerated { .. })));
        assert_eq!(scratch.buffer.len(), 0);
    }

    #[test]
    fn rejects_trailing_literals_above_remaining_budget() {
        let mut scratch = DecoderScratch::new(1024);
        scratch.literals_buffer.resize(1025, b'x');
        assert!(matches!(execute_sequences(&mut scratch, 1024), Err(ExecuteSequencesError::TooManyBytesGenerated { .. })));
        assert_eq!(scratch.buffer.len(), 0);
    }

    #[test]
    fn accepts_exact_block_limit() {
        let mut scratch = DecoderScratch::new(1024);
        scratch.literals_buffer.push(b'x');
        scratch.sequences.push(Sequence { ll: 1, ml: 1023, of: 1 });
        execute_sequences(&mut scratch, 1024).unwrap();
        assert_eq!(scratch.buffer.len(), 1024);
    }
}
