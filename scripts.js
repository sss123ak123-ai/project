// scripts.js
// Mobile Navigation Toggle
document.getElementById('hamburger').addEventListener('click', () => {
  document.querySelector('.nav-links').classList.toggle('active');
});

// Search Filter
document.getElementById('search-input').addEventListener('input', (e) => {
  const searchTerm = e.target.value.toLowerCase();
  const cards = document.querySelectorAll('.card');
  
  cards.forEach(card => {
    const title = card.querySelector('h3').textContent.toLowerCase();
    if (title.includes(searchTerm)) {
      card.style.display = 'block';
    } else {
      card.style.display = 'none';
    }
  });
});

// Vibe Toggle
document.querySelectorAll('.vibe-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    // Update active class
    document.querySelectorAll('.vibe-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    
    // Toggle content
    const vibe = btn.dataset.vibe;
    document.querySelectorAll('.career-content').forEach(content => {
      content.style.display = vibe === 'career' ? 'block' : 'none';
    });
    document.querySelectorAll('.learning-content').forEach(content => {
      content.style.display = vibe === 'learning' ? 'block' : 'none';
    });
  });
});

// Read More Buttons
document.querySelectorAll('.read-more').forEach(button => {
  button.addEventListener('click', () => {
    const key = button.closest('.card').dataset.key;
    window.location.href = `pages/${key}.html`;
  });
});