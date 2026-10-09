
document.addEventListener('DOMContentLoaded', function() {
    const openTransferBtn = document.getElementById('btnOpenTransferModal');
    const transferModal = document.getElementById('transferModal');
    const closeTransferBtn = document.getElementById('closeTransferModalBtn');
    const transferBackdrop = document.getElementById('transferModalBackdrop');

    if (openTransferBtn && transferModal) {
        openTransferBtn.addEventListener('click', function() {
            transferModal.classList.remove('hidden');
        });
        if (closeTransferBtn) {
            closeTransferBtn.addEventListener('click', function() {
                transferModal.classList.add('hidden');
            });
        }
        if (transferBackdrop) {
            transferBackdrop.addEventListener('click', function() {
                transferModal.classList.add('hidden');
            });
        }
    }
});
