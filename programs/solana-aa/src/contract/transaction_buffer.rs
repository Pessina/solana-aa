use anchor_lang::prelude::*;

/*
    TODO: 
    - The current implementation is limited by Solana's heap size (32kb) as the chunks vector needs to be loaded into memory for vector operations. We should consider using zero-copy accounts to avoid this limitation.
    - The current implementation reallocates memory for each transaction, which is inefficient. We should pre-allocate the required memory based on the total chunks size, enabling parallel transaction processing.
*/

const DISCRIMINATOR_SIZE: usize = 8;
const PUBKEY_SIZE: usize = 32;
const U16_SIZE: usize = 2;
const VEC_PREFIX_SIZE: usize = 4;
const CHUNK_OVERHEAD: usize = U16_SIZE + 1 + VEC_PREFIX_SIZE; // index (u16) + is_stored (bool) + vec prefix
const MAX_CHUNK_SIZE: usize = 900;

pub fn init_storage_impl(
    ctx: Context<InitStorage>, 
    data_id: [u8; 32], 
    chunk_index: u16, 
    total_chunks: u16,
    data_hash: [u8; 32], 
    chunk_data: Vec<u8>
) -> Result<()> {
    msg!("Initializing new storage account");
    let storage = &mut ctx.accounts.unified_storage;
    storage.data_id = data_id;
    storage.total_chunks = total_chunks;
    storage.data_hash = data_hash;
    storage.chunks_stored = 1;
    storage.chunks = vec![ChunkData {
        index: chunk_index,
        data: chunk_data,
        is_stored: true
    }];
    
    Ok(())
}

pub fn store_chunk_impl(
    ctx: Context<StoreChunk>, 
    data_id: [u8; 32], 
    chunk_index: u16, 
    total_chunks: u16,
    data_hash: [u8; 32], 
    chunk_data: Vec<u8>
) -> Result<()> {
    require!(chunk_data.len() <= MAX_CHUNK_SIZE, ErrorCode::ChunkTooLarge);
    
    let initial = ctx.accounts.unified_storage.chunks.is_empty();

    require!(!initial, ErrorCode::StorageNotInitialized);
    
    // Verify data consistency
    let storage = &mut ctx.accounts.unified_storage;
    require!(storage.data_id == data_id, ErrorCode::InvalidDataId);
    require!(storage.total_chunks == total_chunks, ErrorCode::InvalidTotalChunks);
    require!(storage.data_hash == data_hash, ErrorCode::InvalidDataHash);    
    require!(chunk_index < total_chunks, ErrorCode::InvalidChunkIndex);

    storage.chunks.push(ChunkData {
        index: chunk_index,
        data: chunk_data.clone(),
        is_stored: true,
    });
    
    storage.chunks_stored = storage.chunks_stored.saturating_add(1);
    
    msg!("Stored chunk {}/{} with size {} bytes", 
        chunk_index + 1, total_chunks, storage.chunks[chunk_index as usize].data.len());
    Ok(())
}

pub fn retrieve_chunk_impl(ctx: Context<RetrieveChunk>, chunk_index: u16) -> Result<Vec<u8>> {
    let storage = &ctx.accounts.unified_storage;
    
    require!(chunk_index < storage.total_chunks, ErrorCode::InvalidChunkIndex);
    
    if chunk_index as usize >= storage.chunks.len() {
        return err!(ErrorCode::ChunkNotAllocated);
    }
    
    require!(storage.chunks[chunk_index as usize].is_stored, ErrorCode::ChunkNotStored);
    
    Ok(storage.chunks[chunk_index as usize].data.clone())
}

pub fn get_data_metadata_impl(ctx: Context<GetDataMetadata>) -> Result<DataMetadata> {
    let storage = &ctx.accounts.unified_storage;
    
    Ok(DataMetadata {
        data_id: storage.data_id,
        total_chunks: storage.total_chunks,
        chunks_stored: storage.chunks_stored,
        data_hash: storage.data_hash,
    })
}

pub fn close_storage_impl(ctx: Context<CloseStorage>) -> Result<()> {
    msg!("Closed storage account. Freed {} chunks", ctx.accounts.unified_storage.chunks_stored);
    
    Ok(())
}


#[derive(Accounts)]
#[instruction(data_id: [u8; 32], chunk_index: u16, total_chunks: u16, data_hash: [u8; 32], chunk_data: Vec<u8>)]
pub struct InitStorage<'info> {
    #[account(
        init_if_needed,
        payer = payer,
        space = calculate_initial_space(),
        seeds = [
            b"unified_storage", 
            payer.key().as_ref(),
            &data_id
        ],
        bump
    )]
    pub unified_storage: Account<'info, UnifiedStorage>,
    
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(data_id: [u8; 32], chunk_index: u16, total_chunks: u16, data_hash: [u8; 32], chunk_data: Vec<u8>)]
pub struct StoreChunk<'info> {
    #[account(
        mut,
        seeds = [
            b"unified_storage", 
            payer.key().as_ref(),
            &data_id
        ],
        bump,
        // TODO: Instead of realloc one by one, we should batch the reallocations
        realloc = unified_storage.to_account_info().data_len() + CHUNK_OVERHEAD + MAX_CHUNK_SIZE,
        realloc::payer = payer,
        realloc::zero = false
    )]
    pub unified_storage: Account<'info, UnifiedStorage>,
    
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

fn calculate_initial_space() -> usize {
    // Base size + space for initial chunks
    DISCRIMINATOR_SIZE + 
    PUBKEY_SIZE +          // data_id
    U16_SIZE +             // total_chunks
    U16_SIZE +             // chunks_stored
    PUBKEY_SIZE +          // data_hash
    VEC_PREFIX_SIZE +      // chunks vector prefix
    U16_SIZE +             // capacity
    (CHUNK_OVERHEAD + MAX_CHUNK_SIZE) // initial chunks
}

#[derive(Accounts)]
#[instruction(chunk_index: u16)]
pub struct RetrieveChunk<'info> {
    #[account(
        seeds = [
            b"unified_storage", 
            payer.key().as_ref(),
            &unified_storage.data_id
        ],
        bump
    )]
    pub unified_storage: Account<'info, UnifiedStorage>,
    pub payer: Signer<'info>,
}

#[derive(Accounts)]
pub struct GetDataMetadata<'info> {
    #[account(
        seeds = [
            b"unified_storage", 
            payer.key().as_ref(),
            &unified_storage.data_id
        ],
        bump
    )]
    pub unified_storage: Account<'info, UnifiedStorage>,
    pub payer: Signer<'info>,
}

#[derive(Accounts)]
pub struct CloseStorage<'info> {
    #[account(
        mut,
        seeds = [
            b"unified_storage", 
            payer.key().as_ref(),
            &unified_storage.data_id
        ],
        bump,
        close = payer
    )]
    pub unified_storage: Account<'info, UnifiedStorage>,
    #[account(mut)]
    pub payer: Signer<'info>,
}

#[account]
pub struct UnifiedStorage {
    pub data_id: [u8; 32],       // Unique identifier for this dataset
    pub total_chunks: u16,       // Total number of chunks in this dataset
    pub chunks_stored: u16,      // Number of chunks stored so far
    pub data_hash: [u8; 32],     // Hash of the entire dataset for integrity verification
    pub chunks: Vec<ChunkData>,  // Vector of all chunks
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Default)]
pub struct ChunkData {
    pub index: u16,              // Index of this chunk (0-based)
    pub is_stored: bool,         // Whether this chunk has been stored
    pub data: Vec<u8>,           // Chunk data
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct DataMetadata {
    pub data_id: [u8; 32],
    pub total_chunks: u16,
    pub chunks_stored: u16,
    pub data_hash: [u8; 32],
}

#[error_code]
pub enum ErrorCode {
    #[msg("Invalid chunk index")]
    InvalidChunkIndex,
    
    #[msg("Chunk not stored")]
    ChunkNotStored,
    
    #[msg("Chunk not yet allocated - need more capacity")]
    ChunkNotAllocated,
    
    #[msg("Invalid data ID")]
    InvalidDataId,
    
    #[msg("Invalid total chunks")]
    InvalidTotalChunks,
    
    #[msg("Invalid data hash")]
    InvalidDataHash,
    
    #[msg("Chunk too large (exceeds maximum size)")]
    ChunkTooLarge,
    
    #[msg("Storage not initialized")]
    StorageNotInitialized,
}
